# -*- coding: utf-8 -*-
import sys
import os

"""
this file aims to add the model into system 
"""
try:
    from pcap_process import *
except ImportError:
    pwd = os.getcwd()
    sys.path.append(pwd + "/data_process/FlowMining/pcap_process.py")

try:
    from pcap_parser import *
except ImportError:
    pwd = os.getcwd()
    sys.path.append(pwd + "/data_process/FlowMining/pcap_parser.py")

try:
    from pcap_explore import *
except ImportError:
    pwd = os.getcwd()
    sys.path.append(pwd + "/data_process/FlowMining/pcap_explore.py")

