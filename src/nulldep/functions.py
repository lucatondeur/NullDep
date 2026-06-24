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

def nulldep_help(subcommands, subcommand_descriptions):
    print("Subcommands:	Descriptions: \n")
    for s in subcommands:
        print(subcommands.get(s) + " 		" + subcommand_descriptions.get(s))

def set_link_state(interface, state):
    # Initialise an independent raw routing bus socket
    rt_socket = nl_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
    
    if state == "up":
        flags = IFF_UP
        netlink_flags = 1 | 1024
    elif state == "down":
        flags = 0
        netlink_flags = 1
        
    change_mask = IFF_UP
    
    idx = socket.if_nametoindex(interface)

    
    ifinfo_payload = struct.pack("<BBHIII", 0, 0, 0, idx, flags, change_mask)
    
    msg_length = 16 + len(ifinfo_payload)
    nl_hdr = main_nl_header(msg_length, RTM_NEWLINK, netlink_flags, 1, 0)
    
    try:
        rt_socket.send(nl_hdr + ifinfo_payload)
        if state == "up":
            print(f"Enabling {interface}")
        elif state == "down":
            print(f"Disabling {interface}")
    finally:
        rt_socket.close()

def set_interface_mode(interface, request_mode, family_id, netlink_socket):
    idx = socket.if_nametoindex(interface)
    attr_idx = attribute(8, NL80211_ATTR_IFINDEX, struct.pack("<I", idx))
    attr_type = attribute(8, NL80211_ATTR_IFTYPE, struct.pack("<I", request_mode))
    attr = attr_idx + attr_type
    genl_hdr = generic_nl_header(NL80211_CMD_SET_INTERFACE, 1, 0)
    msg_length = 16 + len(genl_hdr) + len(attr)
    nl_hdr = main_nl_header(msg_length, family_id, 1, 1, 0)
    
    netlink_socket.send(nl_hdr + genl_hdr + attr)
    print(f"{INTERFACE_MODES.get(request_mode)} mode enabled")
    
def switch_channels(interface, channel, family_id, netlink_socket):
    frequency_mhz = CHANNEL_FREQUENCIES.get(channel, 2437)
    
    idx = socket.if_nametoindex(interface)
    attr_idx = attribute(8, NL80211_ATTR_IFINDEX, struct.pack("<I", idx))
    attr_freq = attribute(8, NL80211_ATTR_WIPHY_FREQ, struct.pack("<I", frequency_mhz))
    attr_width = attribute(8, NL80211_ATTR_WIPHY_CHANNEL_TYPE, struct.pack("<I", NL80211_CHAN_NO_HT))
    attr = attr_idx + attr_freq + attr_width
    
    wiphy_genl_hdr = generic_nl_header(NL80211_CMD_SET_WIPHY, 1, 0)
    
    msg_length = 16 + len(wiphy_genl_hdr) + len(attr)
    wiphy_nl_hdr = main_nl_header(msg_length, family_id, 1, 1, 0)
    
    try:
        netlink_socket.send(wiphy_nl_hdr + wiphy_genl_hdr + attr)
        #print(f"CH: {channel}")
        #reply = netlink_socket.recv(4096)
        #nl_len, nl_type, _, _, _ = struct.unpack("<IHHII", reply[:16])
        #print(f"nl_type = {nl_type}")
    except OSError as e:
        print(f"NetLink Channel Switch Error: {e}")

def scan_networks(sniff_socket, discovered_networks):

    start_time = time.time()
    
    while time.time() - start_time < 0.5:
        try:
            reply = sniff_socket.recv(4096)
        except BlockingIOError and OSError:
            time.sleep(0.01)
            continue

        radiotap_hdr_length = struct.unpack("<H", reply[2:4])[0]
        mac_hdr = reply[radiotap_hdr_length:]
        if mac_hdr[0] == 0x80:
    
            bssid_raw = mac_hdr[16:22]
            frame_body = mac_hdr[24:]
            ie_elements = frame_body[12:]

            if len(ie_elements) >= 2:
                if ie_elements[0] == 0:
                    ssid_len = ie_elements[1]
                    ssid_str = ie_elements[2 : 2 + ssid_len].decode('utf-8', errors='ignore')
                    
                    if not ssid_str.strip():
                        ssid_str = "<hidden SSID>"
                    
                    bssid_str = ":".join(f"{b:02x}" for b in bssid_raw)
                    if discovered_networks.get(ssid_str) != bssid_str:
                        discovered_networks.update({ssid_str: bssid_str})

        if mac_hdr[0] != 0x80:
            continue

def cycle_channels(interface, family_id, netlink_socket):
    
    sniff_socket = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    sniff_socket.bind((interface, 0))
    sniff_socket.setblocking(False)
    
    discovered_networks = {}
    
    channel = 1
    
    sys.stdout.write("\033[2J" + "\033[?25l")
    sys.stdout.flush()
    
    try:
        while True:
            screen = "\033[H"
            switch_channels(interface, channel, family_id, netlink_socket)
            screen = screen + f"CH: {channel}   	BSSID			SSID" + "\n"
            screen = screen + "\n"

            scan_networks(sniff_socket, discovered_networks)
            for i in discovered_networks:
                screen = screen + f"   		{discovered_networks.get(i)}	{i}" + "\n"
                
            sys.stdout.write(screen)


            #print(discovered_networks)
            channel = channel + 1
            if channel > 14:
                channel = 1
                
    except KeyboardInterrupt:
        print("", end="\r")
        sys.stdout.write("\033[?25h" + "Quitting...")
        sys.stdout.flush()
    

    