#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# nl80211 is the Linux NetLink-based interface for wireless tools, which will be managed in order to monitor traffic, hence the name

import socket # Provides low-level networking capabilities
import struct # Allows conversion into binary data
import sys
import os # Allows interaction with operating system

command = sys.argv[0]
if len(sys.argv) == 1:
    subcommand = "-h"

if len(sys.argv) > 1:
    subcommand = sys.argv[1]

if len(sys.argv) > 2:
    interface = sys.argv[2]

if len(sys.argv) > 3:
    mode = sys.argv[3]

subcommands = {
    1: "-h", # help
    2: "dwi", # display wireless interfaces
    3: "sim", # set wireless interface
    4: "scan" # scan wireless networks
}

subcommand_descriptions = {
    1: "help",
    2: "display wireless interfaces",
    3: "set interface mode e.g. managed, monitor",
    4: "scan wireless interfaces"
}


# SYSTEM & NETLINK PLATFORM CONSTANTS
AF_NETLINK = 16 # Address family 16 (NetLink) is the kernel user interface device (LAYER 1)
SOCK_RAW = 3 # Socket type 3 specifies that raw binary should be sent to the driver
NETLINK_GENERIC = 16 # Protocol number 16 (Generic Netlink) acts as a container family for many sub-families, including nl80211 (WiFi) (LAYER 2)

# NETLINK BUS CONTROLLER CONSTANTS
GENL_ID_CTRL = 16 # Generic NetLink ID 16 routes the packet to the NetLink Controller (LAYER 3)
CTRL_CMD_GETFAMILY = 3 # Controller command 3 triggers the ctrl_getfamily function to resolve a family ID (LAYER 4)
CTRL_ATTR_FAMILY_NAME = 2 # Contoller attribute type 2 identifies the following payload as the string name of the target family (LAYER 5)
CTRL_ATTR_FAMILY_ID = 1 # Controller attribute type 1 identifies a response payload containing the requested dynamic family ID (LAYER 5)

# NL80211 WIRELESS CONTROLLER CONSTANTS
NL80211_CMD_GET_INTERFACE = 5 # Command 5 requests information about the wireless interfaces
NL80211_CMD_SET_INTERFACE = 6 # Command 6 alters an existing interface's operational mode
NL80211_ATTR_IFINDEX = 3 # Attribute type 3 holds the interface's numerical index
NL80211_ATTR_IFTYPE = 5 # Attribute type 5 identifies the current operational mode (e.g., managed, monitor)

NL80211_CMD_SET_WIPHY = 2 # Command 2 alters physical radio configurations (like frequency)
NL80211_ATTR_WIPHY = 1 # Attribute 1 targets the physcial radio index (WIPHY ID)
NL80211_ATTR_WIPHY_FREQ = 38 # Attribute 38 declares the absolute target frequency in MHz
NL80211_ATTR_WIPHY_CHANNEL_TYPE = 39 # Attribute 39 sets the channel width layout (e.g., 20MHz)
NL80211_CHAN_NO_HT = 0 # Standard 20MHz legacy channel spacing width

# Maps standard 2.4GHz and 5GHz WiFi channels to their exact kernel Megahertz frequency
CHANNEL_FREQUENCIES = {
    1: 2412, 2: 2417, 3: 2422,
    
    4: 2427, 5: 2432, 6: 2437,
    
    7: 2442, 8: 2447, 9: 2452,
    
    10: 2457, 11: 2462, 12: 2467,
    
    13: 2472, 14: 2484, 36: 5180,
    
    40: 5200, 44: 5220, 48: 5240,
    
    52: 5260, 56: 5280, 60: 5300,
    
    64: 5320, 100: 5500, 104: 5520,
    
    108: 5540, 112: 5560, 116: 5580,
    
    120: 5600, 124: 5620, 128: 5640,
    
    132: 5660, 136: 5680, 140: 5700,
    
    144: 5720, 149: 5745, 153: 5765,
    
    157: 5785, 161: 5805, 165: 5825,
    
    169: 5845, 173: 5865, 177: 5885

}

# NATIVE HARDWARE OPERATIONAL MODES
NL80211_IFTYPE_STATION = 2 # Interface type 2 represents standard station mode for connecting to an access point (Managed Mode)
NL80211_IFTYPE_MONITOR = 6 # Interface type 6 represents raw radio frequency  spectrum monitoring profile (Monitor Mode)

# RTNETLINK (ROUTE BUS) PLATFORM CONSTANTS
NETLINK_ROUTE = 0
RTM_NEWLINK = 16
IFF_UP = 0x1

# AF_PACKET LINK-LAYER NETWORK CONSTANTS
AF_PACKET = 17 # Address family 17 (NetLink) allows the sending and receiving of raw packets directly at the link-layer level
ETH_P_ALL =0x0003 # Protocol filter code to capture absolutely every network frame

# Numerical wireless mode translations
INTERFACE_MODES = {
    NL80211_IFTYPE_STATION: "Managed",
    NL80211_IFTYPE_MONITOR: "Monitor"
}

CIPHER_MAP = {
    0: "NONE",
    1: "WEP",
    2: "TKIP",
    4: "CCMP",
    8: "GCMP"
}

AUTH_MAP = {
    1: "MGT",
    2: "PSK",
    3: "FT/MGT",
    4: "FT/PSK",
    5: "MGT-256",
    6: "PSK-256",
    8: "PSK",
    9: "FT/SAE",
    11: "SUITE-B",
    12: "SUITE-B",
    18: "OWE",
    24: "SAE-384"
}

ENC_MAP = {
    1: "WPA2",
    2: "WPA2",
    3: "WPA2",
    4: "WPA2",
    5: "WPA2",
    6: "WPA2",
    8: "WPA3",
    9: "WPA3",
    11: "WPA3",
    12: "WPA3",
    18: "OPN",
    24: "WPA3"
}

from nulldep.nulldep_help import *
from nulldep.message_construction import *
from nulldep.mode_configuration import *
from nulldep.channel_scanner import *

def main():
    # Initialise NetLink socket
    netlink_socket = nl_socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)

    # Attribute formatted as [Length][Type][Value], where length = 4 bytes + size of name in bytes, type = CTRL_ATTR_FAMILY_NAME, and value = name
    name = b"nl80211\0" # Name of the WiFi subsystem, written as a null-terminated byte string, hence b prior to quotation marks and a null terminator (\0)
    length = 4 + len(name)
    attr = attribute(length, CTRL_ATTR_FAMILY_NAME, name)

    # Generic NetLink Header formatted as [Command][Version][Reserved], where command = CTRL_CMD_GETFAMILY, version = 1, reserved = 0 (When fields are marked as reserved, the kernel strictly expects them to be 0)
    genl_hdr = generic_nl_header(CTRL_CMD_GETFAMILY, 1, 0)

    # Main NetLink Header formatted as [Length][Type][Flags][Sequence][PID], where length = 16 bytes + size of the Generic NetLink Header and attribute in bytes, type = GENL_ID_CTRL, flags = 1 (meaning "request" (NLM_F_REQUEST)), sequence (acts as a tracking number for the message), and PID (identifies the socket belonging to the process) = 0, letting the kernel fill those in
    msg_length = 16 + len(genl_hdr) + len(attr)
    nl_hdr = main_nl_header(msg_length, GENL_ID_CTRL, 1, 0, 0)

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
    
    # family_id is a 2-byte unsigned short (H)
    family_id = attribute_unpack(reply, nl_len, CTRL_ATTR_FAMILY_ID, "<H")
    # print(f"Found nl80211 Family ID: {family_id}")

    if len(sys.argv) >= 1:
        if subcommand == subcommands.get(1):
            nulldep_help(subcommands, subcommand_descriptions)
        
        elif subcommand == subcommands.get(2):
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
                            interface_attr = attribute(8, NL80211_ATTR_IFINDEX, struct.pack("<I", idx))
                        
                            # Generic NetLink Header formatted as [Command][Version][Reserved], where command = NL80211_CMD_GET_INTERFACE, version = 1, reserved = 0 (When fields are marked as reserved, the kernel strictly expects them to be 0)
                            wifi_genl_hdr = generic_nl_header(NL80211_CMD_GET_INTERFACE, 1, 0)
                        
                            # Main NetLink Header formatted as [Length][Type][Flags][Sequence][PID], where length = 16 bytes + size of the Generic NetLink Header and attribute in bytes, type = family_id, flags = 1 (meaning "request" (NLM_F_REQUEST)), sequence (acts as a tracking number for the message), and PID (identifies the socket belonging to the process) = 0, letting the kernel fill those in
                            wifi_msg_length = 16 + len(wifi_genl_hdr) + len(interface_attr)
                            wifi_nl_hdr = main_nl_header(wifi_msg_length, family_id, 1, 1, 0)
                            
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
                            
                            # Unpack the operating mode value as a 4-byte unsigned integer (I) following the 4-byte attribute header, accessing index 0 since struct.unpack() returns a tuple
                            mode_int = attribute_unpack(driver_reply, reply_len, NL80211_ATTR_IFTYPE, "<I")
                            
                            # Map the extracted integer against the INTERFACE_MODES translation dictionary
                            mode_str = INTERFACE_MODES.get(mode_int, f"Unknown ({mode_int})")
                            
                            # Prints in blue
                            print("\033[36m" + f"[{counter}] Interface Name: {iface} | Active Mode: {mode_str}"  + "\033[0m")
                            counter = counter + 1
            except IOError:
                print("Error: Could not read system interface directory.")
                exit()
            
        elif subcommand == subcommands.get(3):
            set_link_state(interface, "down")
            
            if mode == "man":
                request_mode = NL80211_IFTYPE_STATION
                
            if mode == "mon":
                request_mode = NL80211_IFTYPE_MONITOR
                
            set_interface_mode(interface, request_mode, family_id, netlink_socket)
            
            set_link_state(interface, "up")
        
        elif subcommand == subcommands.get(4):
            print()
            #switch_channels(interface, 44, family_id, netlink_socket)
            #scan_networks(interface)
            cycle_channels(interface, family_id, netlink_socket)
                
                
        else:
            print("Unknown subcommand")
        

if __name__ == "__main__":
    main()
