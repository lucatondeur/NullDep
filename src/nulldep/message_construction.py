#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from nulldep.nl80211_monitor import *
import time

def nl_socket(Family, Type, Protocol):
    # Create the socket
    try:
        netlink_socket = socket.socket(Family, Type, Protocol) # socket.socket(Family, Type, Protocol)
        netlink_socket.bind((0, 0)) # bind(Port ID (PID), Multicast Groups) binds zero value to the kernel, which mean that the PID can be set to anything as long as it is unique, and no general broadcast groups are being subscribed to
    # Throws when user has inadequate permissions, as Linux only allows root users to access raw sockets
    except PermissionError:
        print("Error: NetLink access requires root/sudo.")
        exit()
    return netlink_socket

def attribute(Length, Type, Value):
    attr = struct.pack("<HH", Length, Type) + Value # <HH packs two two-byte unsigned shorts (each unsigned short denoted by an H) in "Little Endian" byte order (denoted by <)
    return attr

def generic_nl_header(Command, Version, Reserved):
    genl_hdr = struct.pack("<BBH", Command, Version, Reserved) # <BBH packs two one-byte unsigned chars (each unsigned char denoted by a B) and one two-byte unsigned short (denoted by an H) in "Little Endian" byte order (denoted by <)
    return genl_hdr

def main_nl_header(Length, Type, Flags, Sequence, PID):
    nl_hdr = struct.pack("<IHHII", Length, Type, Flags, Sequence, PID)
    return nl_hdr

def attribute_unpack(reply, reply_length, target_type, target_size):
    if target_size == "<H":
        i = 6 # 4 + 2-byte short (H)
    if target_size == "<I":
        i = 8 # 4 + 4-byte int (I)
    
    # Starting at offset 20, the  message is a series of attributes
    position = 20
    
    while position < reply_length:
        
        # Formatted in "Little Endian" byte order (denoted by <), each attribute starts with a 4-byte header in the following order: H (2-byte length), H (2-byte type)
        attr_length, attr_type = struct.unpack("<HH", reply[position:position+4])
        
        # Only the type that matches the target type is needed
        if attr_type == target_type:
            
            target_id = struct.unpack(target_size, reply[position+4:position+i])[0]
            break
        
        # Move to the next attribute (attributes are aligned to 4 bytes) by rounding the current attribute length up to the nearest multiple of 4
        position += (attr_length + 3) & ~3
    
    return target_id