#!/usr/bin/env python3
import signal
import sys
import subprocess
import os
from scapy.all import *
import enum 
import time
import datetime
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
   
def keyboardInterruptHandler(sig, frame):
    print('You pressed Ctrl+C!')
    print('Exiting...')

def main():
    #intf = input("Please enter the Network Interface to start capture: ")
    #protocol = input("Please enter the protocol to filter: ")
    device = input("Enter Sender/Recvr: ")
    print("Starting Packet Capture! Press Ctrl+C to stop")
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    FNULL = open(os.devnull, 'w')
    filename = device + ".pcap"
    #p_tcpdump = subprocess.Popen(['tcpdump', 'host 10.0.0.1', '-n', '-i', intf,
    p_tcpdump = subprocess.Popen(['tcpdump', 'host 10.0.0.18', '-n',
                  '-w', filename], stdout=subprocess.PIPE, stderr=FNULL)
    signal.pause()
    p_tcpdump.send_signal(subprocess.signal.SIGTERM)
    FNULL.close()

    ################### Finished. Time to exit! ################
    print('Check file \"{}\" for results'.format(filename))
    sys.exit(0)

if __name__ == "__main__":
    main()
