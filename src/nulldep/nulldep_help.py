#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from nulldep.nl80211_monitor import *
import time

def nulldep_help(subcommands, subcommand_descriptions):
    print("Subcommands:	Descriptions: \n")
    for s in subcommands:
        print(subcommands.get(s) + " 		" + subcommand_descriptions.get(s))
    

    