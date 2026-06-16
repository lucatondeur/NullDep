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

# Attribute formatted as [Length][Type][Value], where length = 4 bytes + size of name in bytes, type = CTRL_ATTR_FAMILY_NAME, and value = name
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

# Having now sent the request, the kernel will send back a reply in the socket buffer, which we have to unpack in reverse to how we packed the request

# Receive the kernel's response with a buffer (the maximum amount of data to be received) of 2048 bytes
reply = netlink_socket.recv(2048)

# Unpack the Main NetLink Header in "Little Endian" byte order (denoted by <) in the following order: I (4-byte length), H (2-byte type), H (2-byte flags), I (4-byte sequence), I (4-byte PID)
nl_len, nl_type, nl_flags, nl_seq, nl_pid = struct.unpack("<IHHII", reply[:16])

# A NetLink type of 2 is a NetLink message error (NLMSG_ERROR), meaning the kernel rejected the request
if nl_type == 2:
    print("Error: Kernel returned a NetLink error.")
    exit()
    
# Offset 16 to 20, unpack the Generic NetLink Header in "Little Endian" byte order (denoted by <) in the following order: B (1-byte command), B (1-byte version), H (2-byte reserved)
genl_cmd, genl_ver, _ = struct.unpack("<BBH", reply[16:20])

# Starting at offset 20, the  message is a series of attributes. Of these attributes, we are looking for the one labelled CTRL_ATTR_FAMILY_ID, which contains the dynamic number we need. In the kernel's Controller family, this specific attribute always has an ID of 1
CTRL_ATTR_FAMILY_ID = 1

position = 20
while position < nl_len:
    # Formatted in "Little Endian" byte order (denoted by <), each attribute starts with a 4-byte header in the following order: H (2-byte length), H (2-byte type)
    attr_len, attr_type = struct.unpack("<HH", reply[position:position+4])
    
    # Only the type that matches the target ID (1) is needed
    if attr_type == CTRL_ATTR_FAMILY_ID:
        # The ID itself is a 2-byte unsigned short (H), which follows the 4-byte header, hence the offset. struct.unpack() returns a tuple, hence [0] to access index 0
        family_id = struct.unpack("<H", reply[position+4:position+6])[0]
        # print(f"Found nl80211 Family ID: {family_id}")
        break
    
    # Move to the next attribute (attributes are aligned to 4 bytes) by rounding the current attribute length up to the nearest multiple of 4
    position += (attr_len + 3) & ~3

# nl80211 wireless constants
NL80211_CMD_GET_INTERFACE = 5 # Command 5 requests information about the wireless interfaces
NL80211_ATTR_IFINDEX = 3 # Attribute type 3 holds the interface's numerical index
NL80211_ATTR_IFTYPE = 5 # Attribute type 5 identifies the current operation mode (e.g., managed, monitor)

# Numerical wireless mode translations
INTERFACE_MODES = {
    2: "Managed",
    6: "Monitor"
}

# Get raw interface names from the file system
try:
    # print("\n-------- Discovered Wireless Interfaces --------")
    counter = 0
    with open("/proc/net/dev", "r") as f:
        lines = f.readlines()[2:]
        for line in lines:
            iface = line.split()[0].replace(":", "")
            
            if iface != "lo" and not iface.startswith("eth") and not iface.startswith("docker"):
                try:
                    idx = socket.if_nametoindex(iface)
                except OSError:
                    continue
                
                # Attribute formatted as [Length][Type][Value] by concatenating a 4-byte attribute header (length = 4 bytes + size of hardware index (4 bytes), type = NL80211_ATTR_IFINDEX) with a 4-byte payload (value = idx)
                interface_attr = struct.pack("<HH", 8, NL80211_ATTR_IFINDEX) + struct.pack("<I", idx) # <HH packs two two-byte unsigned shorts (each unsigned short denoted by an H) in "Little Endian" byte order (denoted by <) and <I packs a four-byte unsigned int
                
                # Generic NetLink Header formatted as [Command][Version][Reserved], where command = NL80211_CMD_GET_INTERFACE, version = 1, reserved = 0 (When fields are marked as reserved, the kernel strictly expects them to be 0)
                wifi_genl_hdr = struct.pack("<BBH", NL80211_CMD_GET_INTERFACE, 1, 0) # <BBH packs two one-byte unsigned chars (each unsigned char denoted by a B) and one two-byte unsigned short (denoted by an H) in "Little Endian" byte order (denoted by <)
                
                # Main NetLink Header formatted as [Length][Type][Flags][Sequence][PID], where length = 16 bytes + size of the Generic NetLink Header and attribute in bytes, type = family_id, flags = 1 (meaning "request" (NLM_F_REQUEST)), and sequence (acts as a tracking number for the message) and PID (identifies the socket belonging to the process) = 0, letting the kernel fill those in
                wifi_msg_length = 16 + len(wifi_genl_hdr) + len(interface_attr)
                wifi_nl_hdr = struct.pack("<IHHII", wifi_msg_length, family_id, 1, 1, 0) # <IHHII packs three four-byte unsigned ints (each unsigned int denoted by an I) and two two-byte unsigned shorts (denoted by an H) in "Little Endian" byte order (denoted by <)
                
                # Sends full packet to the kernel
                netlink_socket.send(wifi_nl_hdr + wifi_genl_hdr + interface_attr)
                
                # Having now sent the request, the kernel will send back a reply in the socket buffer, which we have to unpack in reverse to how we packed the request
                
                # Receive the kernel's response with a buffer (the maximum amount of data to be received) of 4096 bytes
                driver_reply = netlink_socket.recv(4096)
                
                # Unpack the Main NetLink Header in "Little Endian" byte order (denoted by <) in the following order: I (4-byte length), H (2-byte type), H (2-byte flags), I (4-byte sequence), I (4-byte PID)
                reply_len, _, _, _, _ = struct.unpack("<IHHII", driver_reply[:16])
                
                # Initialise the binary scanning pointer at byte offset 20, skipping past the 16-byte Main NetLink Header and the 4-byte Generic NetLink Header to reach the start of the response attributes
                position = 20
                
                # Initialise a default state string for the active interface mode in case the driver fails to return a valid operating type attribute
                mode_str = "Unknown"
                
                # Iterate through the remainder of the packet payload
                while position < reply_len:
                    # Formatted in "Little Endian" byte order (denoted by <), each attribute starts with a 4-byte header in the following order: H (2-byte length), H (2-byte type)
                    attr_len, attr_type = struct.unpack("<HH", driver_reply[position:position+4])
                    
                    # Only the type that matches the NL80211_ATTR_IFTYPE constant is needed
                    if attr_type == NL80211_ATTR_IFTYPE:
                        
                        # Unpack the operating mode value as a 4-byte unsigned integer (I) following the 4-byte attribute header, accessing index 0 since struct.unpack() returns a tuple
                        mode_int = struct.unpack("<I", driver_reply[position+4:position+8])[0]
                        
                        # Map the extracted integer against the INTERFACE_MODES translation dictionary
                        mode_str = INTERFACE_MODES.get(mode_int, f"Unknown ({mode_int})")
                        break
                    
                    # Move to the next attribute (attributes are aligned to 4 bytes) by rounding the current attribute length up to the nearest multiple of 4
                    position += (attr_len + 3) & ~3
                
                # Prints in blue
                print("\033[36m" + f"[{counter}] Interface Name: {iface} | Active Mode: {mode_str}"  + "\033[0m")
                counter = counter + 1
except IOError:
    print("Error: Could not read system interface directory.")
    exit()
    

