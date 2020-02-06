#!/usr/bin/env python3
"""Prints all established vpn tunnels
"""
import requests
import xmltodict
from credential import *
import pprint

requests.packages.urllib3.disable_warnings()

# if credential.py file is not available, uncomment, locate ip address and token
#PANOS_IP_ADDR = ""
#PANOS_API_TOKEN = ""

url = "https://{}/api/".format(PANOS_IP_ADDR)


def get_p1_tunnels():
    querystring = {"type": "op", "cmd": "<show><vpn><ike-sa><summary></summary></ike-sa></vpn></show>", "key":PANOS_API_TOKEN}
    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    p1_list = response_dict['response']['result']['entry']
    return p1_list


def get_p2_tunnels():
    querystring = {"type": "op", "cmd": "<show><vpn><ipsec-sa><summary></summary></ipsec-sa></vpn></show>", "key":PANOS_API_TOKEN}
    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    p2_list = response_dict['response']['result']['entries']['entry']
    return p2_list


def get_disconnected_tunnels():
    querystring = {"type": "op", "cmd": "<show><vpn><tunnel></tunnel></vpn></show>", "key":PANOS_API_TOKEN}
    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    all_tunnels_dict = response_dict['response']['result']['entries']['entry']
    connected_tunnels_dict = get_p2_tunnels()
    connected_tunnels_list = []
    for item in connected_tunnels_dict:
        connected_tunnels_list.append(item['name'])
    print("#" * 50)
    print("Currently Non-Established Tunnels:")
    print("-" * 50)
    for tunnel in all_tunnels_dict:
        if tunnel['name'] not in connected_tunnels_list:
            print(tunnel['name'])
    print("#" * 50)


def print_p1_tunnels():
    vpn_p1_list = get_p1_tunnels()
    print("{:^20} {:^20} {:^20}".format("P1 Tunnel Name", "Created", "Expires"))
    print("{:^20} {:^20} {:^20}".format("-" * 20, "-" * 20, "-" * 20))
    for entry in vpn_p1_list:
        name = entry['name']
        created = entry['created']
        expires = entry['expires']
        print("{:<20} {:>20} {:>20}".format(name, created, expires))



def print_p2_tunnels():
    vpn_p2_list = get_p2_tunnels()
    print("{:^50} {:^40} {:^20}".format("P2 Tunnel Name", "IKE-GW", "Life"))
    print("{:^50} {:^40} {:>20}".format("-" * 50, "-" * 40, "-" * 20))
    for entry in vpn_p2_list:
        name = entry['name'].strip()
        gw = entry['gateway']
        life = entry['life'].strip()
        print("{:<50} {:<40} {:>20}".format(name, gw, life))


def main():
    print_p1_tunnels()
    print_p2_tunnels()
    print()
    get_disconnected_tunnels()


if __name__ == '__main__':
    main()
