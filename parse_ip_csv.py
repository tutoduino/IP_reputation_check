#!/usr/bin/python3
# -*- coding: utf8 -*-

"""
This program parses a CSV file to extract IP addresses. 
IP addresses must be in the first row of the CSV file with ";" delimiter. 
IP addresses are displayed in stdin.
V1.0
23 october 2022
MIT licence
https://tutoduino.fr/
"""

import argparse
import os
import sys
import csv


def checkArgs():
    """ 
    Parse the arguments 
    Should have only one argument which is the name of the CSV file to parse
    Returns the CSV file name
    """
    parser = argparse.ArgumentParser(
        description='Parse CSV file to extract all public IP V4 addresses')
    parser.add_argument("csv", help="CSV file")
    args = parser.parse_args()
    return args.csv


def process_csv(file_name):
    """
    Process the CSV file
    Returns all IP adresses without duplicate
    """
    ip_addr_list = []

    try:
        with open(file_name, 'r') as csv_file:
            reader = csv.reader(csv_file, delimiter=";")
            for row in reader:
                if row[0] not in ip_addr_list:
                    ip_addr_list.append(row[0])
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit()
        
    return ip_addr_list


def print_ip_list(ip_addr_list):
    """
    Print to stdin the list of IP addresses    
    """
    for ip_addr in ip_addr_list:
        print(ip_addr)


def main():
    """
    Parse the CSV file given as parameter and print the list
    of IP addresses it contains to stdin
    """
    print_ip_list(process_csv(checkArgs()))


if __name__ == '__main__':
    main()
