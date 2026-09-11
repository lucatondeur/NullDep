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


def scan_networks(sniff_socket, discovered_networks, discovered_clients):

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
                    
                    pos = 0
                    
                    exact_channel, enc, cipher, auth = "?", "?", "?", "?"
                    
                    channel_found = False
                    
                    while pos < len(ie_elements) - 2:
                        element_id = ie_elements[pos]
                        element_len = ie_elements[pos+1]
                        
                        
                        if element_id == 3 and not channel_found:
                            exact_channel = ie_elements[pos+2]
                            channel_found = True
                        if element_id == 61 and not channel_found:
                            exact_channel = ie_elements[pos+2]
                            channel_found = True
                        
                            
                        if element_id == 48:
                            try:
                                rsn_bytes = ie_elements[pos + 2 : pos + 2 + element_len]
                                
                                cipher_bytes = rsn_bytes[11]
                                
                                cipher = CIPHER_MAP.get(cipher_bytes, "?")
                                
                                auth_bytes = rsn_bytes[17]
                                
                                auth = AUTH_MAP.get(auth_bytes, "?")
                                enc = ENC_MAP.get(auth_bytes, "?")
                            except IndexError:
                                pass
                            
                        pos += 2 + element_len
                    
                    if not ssid_str.strip():
                        ssid_str = "<hidden SSID>"
                    
                    bssid_str = ":".join(f"{b:02x}" for b in bssid_raw)
                    discovered_networks[bssid_str] = [ssid_str, exact_channel, enc, cipher, auth]

        elif mac_hdr[0] == 72:
            router_raw = mac_hdr[4:10]
            router_str = ":".join(f"{r:02x}" for r in router_raw)
            station_raw = mac_hdr[10:16]
            station_str = ":".join(f"{s:02x}" for s in station_raw)
            
            if station_str != "ff:ff:ff:ff:ff:ff" and station_str != router_str:
                discovered_clients[station_str] = router_str

def cycle_channels(interface, family_id, netlink_socket):
    try:
        sniff_socket = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
        sniff_socket.bind((interface, 0))
        sniff_socket.setblocking(False)

        print()

        discovered_networks = {}
        discovered_clients = {}

        channel = 1

        sys.stdout.write("\033[2J" + "\033[?25l")
        sys.stdout.flush()

        try:
            while True:
                screen = "\033[H\033[J"
                switch_channels(interface, channel, family_id, netlink_socket)
                screen += f"   Scanning channel {channel:<2}" + "\033[K\n\n"
                screen += f"   {'BSSID':<18}   {'CH':<4}   {'ENC':<5}   {'CIPHER':<7}   {'AUTH':<5}   {'SSID':<18}   {'CLIENTS'}" + "\033[K\n\n"

                scan_networks(sniff_socket, discovered_networks, discovered_clients)
                for bssid, info in discovered_networks.items():
                    client_count = sum(1 for clients, ap in discovered_clients.items() if ap == bssid)
                    screen += f"   {bssid:<18}   {info[1]:<4}   {info[2]:<5}   {info[3]:<7}   {info[4]:<5}   {info[0]:<18}   {client_count}" + "\033[K\n"

                screen += "\033[K\n"
                screen += f"   {'BSSID':<18}   {'STATION':<18}" + "\033[K\n\n"

                for client, ap in discovered_clients.items():
                    screen += f"   {ap:<18}   {client:<18}" + "\033[K\n"

                sys.stdout.write(screen)
                sys.stdout.flush()

                if channel == 14:
                    channel = 36

                elif channel < 14:
                    channel += 1

                elif channel == 144:
                    channel = 149

                elif channel >= 36:
                    channel += 4

                if channel > 177:
                    channel = 1

        except KeyboardInterrupt:
            print("", end="\r")
            sys.stdout.write("\033[?25h" + "Quitting...")
            sys.stdout.flush()
    except OSError:
        print("Error: wireless interface not found")
