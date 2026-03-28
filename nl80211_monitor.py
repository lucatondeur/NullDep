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