#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from nulldep.nl80211_monitor import *
import time
    
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
                    if discovered_networks.get(bssid_str) != ssid_str:
                        discovered_networks.update({bssid_str: ssid_str})

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
                screen = screen + f"   		{i}	{discovered_networks.get(i)}" + "\n"
                
            sys.stdout.write(screen)


            #print(discovered_networks)
            channel = channel + 1
            if channel > 14:
                channel = 1
                
    except KeyboardInterrupt:
        print("", end="\r")
        sys.stdout.write("\033[?25h" + "Quitting...")
        sys.stdout.flush()