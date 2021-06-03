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
   
class DIRECTION(enum.Enum): 
  DIR_ERROR = 0
  SENDING   = 1
  RECEIVING = 2

protos = { "UDP": 17, "TCP": 6}

def calculateResponseTime(pkt_sent, pkt_recv):
  orig_stdout = sys.stdout
  f = open('logs.txt', 'w')
  sys.stdout = f

  pkt_rtt = dict()
  for port in pkt_sent:
    ts_sent = pkt_sent[port]
    try:
      ts_recv = pkt_recv[port]
    except:
      print('No reponse from port:{}'.format(port))
      continue

    if (len(ts_sent) != len(ts_recv)):
      print('No response from port:{}. Cannot find resp time!'.format(port))
      continue
    
    resp_time = dict()
    for (seq, sent) in ts_sent.items():
      try:
        recv = ts_recv[seq]
      except:
        print('No reponse from port:{} for seq num:{}'.format(port, seq))
        continue

      for s, r in zip(sent, recv):
        if seq in resp_time:
          resp_time[seq].append((r - s) * 1000)
        else:
          rtt = (r - s) * 1000
          resp_time[seq] = [rtt]

    pkt_rtt[port] = resp_time

  formatted_rtt = []
  # print('Response time (ms) for packets sorted by port numbers:\n')
  for port in sorted(pkt_rtt.keys()):
    #print('Flow #{}: {}'.format(port, pkt_rtt[port]))
    for seq in pkt_rtt[port]:
      formatted_rtt = formatted_rtt + pkt_rtt[port][seq]
  formatted_rtt.sort()
  print('{}'.format(formatted_rtt))
    #print('Port {}: {}'.format(port, pkt_rtt[port].values()))
  
  sys.stdout = orig_stdout
  f.close()
  return(pkt_rtt)

def analysePacketCapture(protocol, filename, src_ip, dst_ip):
    timestamps = dict()
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
      #Start processing
      try:
        ether_pkt = Ether(pkt_data)
      except:
        continue

      try:
        ip_pkt = ether_pkt[IP]
      except:
        #print('Skipping packet')
        continue

      if (ip_pkt.src != src_ip) or (ip_pkt.dst != dst_ip):
          #print('src_ip and dst_ip do not match')
          continue

      if ip_pkt.proto != int(protos[protocol]):
        # Ignore non-TCP packet
        print('Not an interesting protocol')
        continue

      try:
        transport_layer = ip_pkt[protocol]
      except:
        continue

      if (transport_layer.sport != transport_layer.dport):
        # Src Port and Dst Port should match
        print('Port Numbers do not match')
        continue

      if not(ether_pkt.haslayer(Raw)):
        #No seq number
        #print('No seq number')
        continue
      else:
        seq_num = int(ether_pkt[Raw].load)

      # Get timestamp
      ts = pkt_metadata.sec + (pkt_metadata.usec / 1000000)

      if transport_layer.sport in timestamps:
        if seq_num in timestamps[transport_layer.sport]:
          timestamps[transport_layer.sport][seq_num].append(ts)
        else:
          timestamps[transport_layer.sport][seq_num] = []
          timestamps[transport_layer.sport][seq_num].append(ts)
      else:
        timestamps[transport_layer.sport] = dict()
        if seq_num in timestamps[transport_layer.sport]:
          timestamps[transport_layer.sport][seq_num].append(ts)
        else:
          timestamps[transport_layer.sport][seq_num] = []
          timestamps[transport_layer.sport][seq_num].append(ts)

    return(timestamps)

def processPacketCapture(protocol, src_ip, dst_ip):
  print('Calculating response time for packets... \n')
  pkt_sent = analysePacketCapture(protocol, "sender.pcap", 
                                                src_ip, dst_ip) 
  #print(pkt_sent)
  pkt_recv = analysePacketCapture(protocol, "receiver.pcap", 
                                                src_ip, dst_ip)
  #print(pkt_recv)
  pkt_rtt = calculateResponseTime(pkt_sent, pkt_recv)

def main():
    if os.path.exists("demofile.txt"):
        os.remove("logs.txt")
    protocol = 'UDP'#input('Please enter the protocol to filter: ')
    src_ip = '10.0.0.18'#input('Enter source IP: ')
    dst_ip = '10.0.0.2'#input('Enter destination IP: ')
    processPacketCapture(protocol, src_ip, dst_ip)
    ################### Finished. Time to exit! ################
    print('Done')
    print('Check file \"logs.txt\" for results')
    os.remove('sender.pcap')
    os.remove('receiver.pcap')
    sys.exit(0)

if __name__ == "__main__":
    main()
