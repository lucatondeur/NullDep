#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from nulldep.nl80211_monitor import *
import time

def nulldep_help(subcommands, subcommand_descriptions):
    print("\nSubcommands: \n")
    for s in subcommands:
        cmd_and_args = f"{subcommands.get(s)} {subcommand_arguments.get(s)}"
        print(f"{cmd_and_args:<23}: {subcommand_descriptions.get(s)}")
    

    
