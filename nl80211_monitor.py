# nl80211 is the Linux NetLink-based interface for wireless tools, which will be managed in order to monitor traffic, hence the name

import socket # Provides low-level networking capabilities
import struct # Allows conversion into binary data
import os # Allows interaction with operating system


# Netlink constants
AF_NETLINK = 16 # Address family 16 (NetLink) is the kernel user interface device (LAYER 1)
SOCK_RAW = 3 # Socket type 3 specifies that raw binary should be sent to ther driver
NETLINK_GENERIC = 16 # Protocol number 16 (Generic Netlink) acts as a container family for many sub-families, including nl80211 (WiFi) (LAYER 2)

# Create the socket
try:
    netlink_socket = socket.socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) # socket.socket(Family, Type, Protocol)
    netlink_socket.bind((0, 0)) # bind(Port ID (PID), Multicast Groups) binds zero value to the kernel, which mean that the PID can be set to anything as long as it is unique, and no general broadcast groups are being subscribed to
# Throws when user has inadequate permissions, as Linux only allows root users to access raw sockets
except PermissionError:
    print("Error: NetLink access requires root/sudo.")
    exit()
    
# Message constants
GENL_ID_CTRL = 16 # Generic NetLink ID 16 routes the packet to the NetLink Controller (LAYER 3)
CTRL_CMD_GETFAMILY = 3 # Controller command 3 triggers the ctrl_getfamily function to resolve a family ID (LAYER 4)
CTRL_ATTR_FAMILY_NAME = 2 # Attribute type 2 identifies the following payload as the string name of the target family (LAYER 5)

# Attribute formatted as [Length][Type][Value], where length = 4 bytes + size of name in bytes, type = CTRL_ATTR_FAMILY_NAME, and Value = name
name = b"nl80211\0" # Name of the WiFi subsystem, written as a null-terminated byte string, hence b prior to quotation marks and a null terminator (\0)
attr = struct.pack("<HH", 4 + len(name), CTRL_ATTR_FAMILY_NAME) + name # <HH packs two two-byte unsigned shorts (each unsigned short denoted by an H) in "Little Endian" byte order (denoted by <)

# Generic NetLink Header formatted as [Command][Version][Reserved], where command = CTRL_CMD_GETFAMILY, version = 1, reserved = 0 (When fields are marked as reserved, the kernel strictly expects them to be 0)
genl_hdr = struct.pack("<BBH", CTRL_CMD_GETFAMILY, 1, 0) # <BBH packs two one-byte unsigned chars (each unsigned char denoted by a B) and one two-byte unsigned short (denoted by an H) in "Little Endian" byte order (denoted by <)

# Main NetLink Header formatted as [Length][Type][Flags][Sequence][PID], where length = 16 bytes + size of the Generic NetLink Header and attribute in bytes, type = GENL_ID_CTRL, flags = 1 (meaning "request" (NLM_F_REQUEST)), and sequence (acts as a tracking number for the message) and PID (identifies the socket belonging to the process) = 0, letting the kernel fill those in
msg_length = 16 + len(genl_hdr) + len(attr)
nl_hdr = struct.pack("<IHHII", msg_length, GENL_ID_CTRL, 1, 0, 0) # <IHHII packs three four-byte unsigned ints (each unsigned int denoted by an I) and two two-byte unsigned shorts (denoted by an H) in "Little Endian" byte order (denoted by <)

# Full packet formatted as [Main NetLink Header][General NetLink Header][Attribute]
full_packet = nl_hdr + genl_hdr + attr

# Sends full packet to the kernel
netlink_socket.send(full_packet)