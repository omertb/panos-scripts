#!/usr/bin/env python3
"""Prints established sessions according to entered
source, destination IP addresses and destination port.

"""
import requests
import xmltodict
from credential import *

requests.packages.urllib3.disable_warnings()

# if credential.py file is not available, uncomment, locate ip address and token
#PANOS_IP_ADDR = ""
#PANOS_API_TOKEN = ""

url = "https://{}/api/".format(PANOS_IP_ADDR)


class colors:
    reset = '\033[0m'
    bold = '\033[01m'
    underline = '\033[04m'

    class fg:
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        orange = '\033[33m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'

    class bg:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'


class IsValid:
    @staticmethod
    def addr(ip_addr):
        octets = ip_addr.split(".")
        if len(octets) != 4:
            # print "must have 4 octets!"
            return False
        else:
            for i, octet in enumerate(octets):
                try:
                    octets[i] = int(octet)
                except ValueError:
                    # invalid input if not convertible to integer
                    return False
            first_octet, second_octet, third_octet, fourth_octet = octets
            valid_ip = True
            if first_octet < 1:
                valid_ip = False
            elif first_octet > 223:
                valid_ip = False
            elif first_octet == 127:
                valid_ip = False
            if first_octet == 169 and second_octet == 254:
                valid_ip = False
            # Check 2nd - 4th octets
            for octet in (second_octet, third_octet, fourth_octet):
                if (octet < 0) or (octet > 255):
                    valid_ip = False
        return valid_ip

    @staticmethod
    def port(port):
        try:
            port_int = int(port)
        except ValueError:
            return False
        if 0 < port_int < 65536:
            return True
        else:
            return False


def get_session_info(src, dst, dport) -> dict:
    src_filter = ""
    dst_filter = ""
    dport_filter = ""
    if src != "":
        src_filter = "<source>{}</source>".format(src)
    if dst != "":
        dst_filter = "<destination>{}</destination>".format(dst)
    if dport != "":
        dport_filter = "<destination-port>{}</destination-port>".format(dport)
    querystring = {"type":"op",
                   "cmd":"<show><session><all><filter>{}{}{}</filter></all></session></show>".format(src_filter,
                                                                                                     dst_filter,
                                                                                                     dport_filter),
                   "key":PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    session_info_list = response_dict['response']['result']
    return session_info_list


def print_session_table(sessions):
    proto_list = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 50: 'ESP'}
    heading = "{:^15} {:^10} {:^15} {:^10} {:^30} {:^5} {:^8} {:^15} {:^10} {:^15} {:^10}".format("Src IP", "Src Port",
                                                                                              "Dst IP", "Dst Port",
                                                                                              "Application", "Proto",
                                                                                              "Bytes", "Src NAT IP",
                                                                                              "SNAT Port", "Dst NAT IP",
                                                                                              "DNAT Port")
    print(colors.bold + colors.fg.orange + heading + colors.reset)
    print(colors.bold + colors.fg.orange +
          "{:^15} {:^10} {:^15} {:^10} {:^30} {:^5} {:^8} {:^15} {:^10} {:^15} {:^10}".format("-" * 15, "-" * 10,
                                                                                              "-" * 15, "-" * 10,
                                                                                              "-" * 30, "-" * 5,
                                                                                              "-" * 8, "-" * 15,
                                                                                              "-" * 10, "-" * 15,
                                                                                              "-" * 10)
          + colors.reset)

    file = open("./last_sessions_file.txt", "w")
    file.write(heading + "\n")

    for entry in sessions:
        pnum = int(entry['proto'])
        b_int = int(entry['total-byte-count'])
        if 1024 < b_int < 1024*1024:
            bytes = str(round(b_int/1024, 1)) + " K"
        elif b_int > 1024*1024:
            bytes = str(round(b_int/(1024*1024), 1)) + " M"
        else:
            bytes = str(b_int)
        source = entry['source']
        dst = entry['dst']
        sport = entry['sport']
        dport = entry['dport']
        app = entry['application']
        proto = proto_list[pnum]
        xsource = entry['xsource'] if entry['srcnat'] == 'True' else ""
        xsport = entry['xsport'] if entry['srcnat'] == 'True' else ""
        xdst = entry['xdst'] if entry['dstnat'] == 'True' else ""
        xdport = entry['xdport'] if entry['dstnat'] == 'True' else ""
        line = "{:<15} {:^10} {:^15} {:^10} {:^30} {:^5} {:^8} {:^15} {:^10} {:^15} {:^10}".format(source, sport, dst,
                                                                                                  dport, app, proto,
                                                                                                  bytes, xsource,
                                                                                                  xsport, xdst, xdport)
        print(colors.fg.green + line + colors.reset)
        file.write(line + "\n")


def main():
    print(colors.bold + colors.underline + colors.fg.green + "SESSION EXPLORER (:" + colors.reset)
    while True:
        src = input("{:<50} {}".format("Enter Source IP Address (leave blank for any)", ": "))
        if src == "":
            break
        if not IsValid.addr(src):
            print("Invalid IP Address, Try Again!\n")
            continue
        break
    while True:
        dst = input("{:<50} {}".format("Enter Destination IP Address (leave blank for any)", ": "))
        if dst == "":
            break
        if not IsValid.addr(dst):
            print("Invalid IP Address, Try Again!\n")
            continue
        break
    while True:
        dport = input("{:<50} {}".format("Enter Destination Port (leave blank for any)", ": "))
        if dport == "":
            break
        if not IsValid.port(dport):
            print("Invalid Port Number, Try Again!\n")
            continue
        break

#    src = ""
#    dst = ""
#    dport = ""
    session_list = get_session_info(src, dst, dport)
    if session_list is None:
        print("No session found.")
    else:
        print_session_table(session_list['entry'])


if __name__ == "__main__":
    main()
