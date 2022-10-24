#!/usr/bin/python3
# -*- coding: utf8 -*-
#
import argparse
import os
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import sys

def checkArgs():
    """ 
    Parse the arguments 
    Should have only one argument which is the name of the PCAP file to parse
    If the file exists the function returns the PCAP file name
    If the file does not exists the function returns "error"
    """
    parser = argparse.ArgumentParser(
        description='Parse PCAP file to extract all public IP V4 addresses')
    parser.add_argument("pcap", help="PCAP file")
    args = parser.parse_args()
    return args.pcap


def process_pcap(file_name):
    """
    Process the PCAP file
    Returns all IP source and destination adresses without duplicate
    """
    ip_addr_list = []
    try:
        for (pkt_data, pkt_metadata) in RawPcapReader(file_name):
            ether_pkt = Ether(pkt_data)
            if not ether_pkt.haslayer(IP):
                continue
            if ether_pkt[IP].src not in ip_addr_list:
                ip_addr_list.append(ether_pkt[IP].src)
            if ether_pkt[IP].dst not in ip_addr_list:
                ip_addr_list.append(ether_pkt[IP].dst)
    except FileNotFoundError as e:
        print(e, file = sys.stderr)
        sys.exit()

    return ip_addr_list



def print_ip_list(ip_addr_list):
    for ip_addr in ip_addr_list:
        print(ip_addr)

def main():
    print_ip_list(process_pcap(checkArgs()))


if __name__ == '__main__':
    main()
