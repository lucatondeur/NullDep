#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from nulldep.nl80211_monitor import *
import time

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

    try:
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
    except OSError:
        return

def set_interface_mode(interface, request_mode, family_id, netlink_socket):
    try:
        idx = socket.if_nametoindex(interface)
        attr_idx = attribute(8, NL80211_ATTR_IFINDEX, struct.pack("<I", idx))
        attr_type = attribute(8, NL80211_ATTR_IFTYPE, struct.pack("<I", request_mode))
        attr = attr_idx + attr_type
        genl_hdr = generic_nl_header(NL80211_CMD_SET_INTERFACE, 1, 0)
        msg_length = 16 + len(genl_hdr) + len(attr)
        nl_hdr = main_nl_header(msg_length, family_id, 1, 1, 0)

        netlink_socket.send(nl_hdr + genl_hdr + attr)
        print(f"{INTERFACE_MODES.get(request_mode)} mode enabled")
    except OSError:
        print("Error: wireless interface not found")
