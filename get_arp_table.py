#!/usr/bin/env python3
"""Prints ARP Table
"""
import requests
import xmltodict
from credential import *

requests.packages.urllib3.disable_warnings()

# if credential.py file is not available, uncomment, locate ip address and token
#PANOS_IP_ADDR = ""
#PANOS_API_TOKEN = ""

url = "https://{}/api/".format(PANOS_IP_ADDR)


def get_arp():
    querystring = {"type": "op", "cmd": "<show><arp><entry name = 'all'/></arp></show>", "key":PANOS_API_TOKEN}
    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    arp_list = response_dict['response']['result']['entries']['entry']
    return arp_list


def print_arp():
    arp_table = get_arp()
    print("{:^15} {:^20} {:^6} {:^20}".format("IP Address", "MAC Address", "TTL", "Interface"))
    print("{:^15} {:^20} {:^6} {:^20} ".format("-" * 15, "-" * 20, "-" * 6, "-" * 11))
    for entry in arp_table:
        ip = entry['ip']
        mac = entry['mac']
        iface = entry['interface']
        ttl = entry['ttl']
        print("{:<15} {:^20} {:>6} {:^20}".format(ip, mac, ttl, iface))


def main():
    print_arp()


if __name__ == '__main__':
    main()
