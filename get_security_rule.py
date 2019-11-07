#!/usr/bin/env python3
"""Gets and prints related security rules
against source-destination ip address and
destination port number.
"""
import requests
import xmltodict
# my local files:
from credential import *
from ipportvalidation import *

requests.packages.urllib3.disable_warnings()

# if credential.py file is not available, uncomment, locate ip address and token
# PANOS_IP_ADDR = ""
# PANOS_API_TOKEN = ""

url = "https://{}/api/".format(PANOS_IP_ADDR)


def get_security_rule(src, dst, dport, proto) -> list:
    querystring = {"type": "op",
                   "cmd": "<test><security-policy-match><source>{}</source><destination>{}</destination>"
                          "<destination-port>{}</destination-port><protocol>{}</protocol><show-all>yes</show-all>"
                          "</security-policy-match></test>".format(src, dst, dport, proto),
                   "key": PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)
    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    sec_rule_list = response_dict['response']['result']['rules']['entry']
    return sec_rule_list


def print_security_rule(sec_rules_list):
    print("\nRelated Security Policy Rules:")
    print("-" * 30)

    for rule in sec_rules_list:
        print(rule)
    print("-" * 30)


def main():
    proto_dict = {'TCP': '6', 'UDP': '17', 'ICMP': '1', 'ESP': '50'}
    p_num = '6'  # default protocol is tcp
    while True:
        src = input("{:<35} {}".format("Enter Source IP Address", ":  "))
        if IsValid.addr(src):
            break
        else:
            print("\nInvalid IP Address, Try Again!")
            continue
    while True:
        dst = input("{:<35} {}".format("Enter Destination IP Address", ":  "))
        if IsValid.addr(dst):
            break
        else:
            print("\nInvalid IP Address, Try Again!")
            continue
    while True:
        dport = input("{:<35} {}".format("Enter Destination Port", ":  "))
        if IsValid.port(dport):
            break
        else:
            print("\nInvalid Port Number, Try Again!")
            continue
    while True:
        proto = input("{:<35} {}".format("Enter Valid Protocol (Default: TCP)", ":  "))
        if not proto:
            break
        try:
            p_num = proto_dict[proto.upper()]
            break
        except KeyError:
            print("\nNot a valid input, Try Again!")
            continue

    sec_rules_list = get_security_rule(src, dst, dport, p_num)

    print_security_rule(sec_rules_list)


if __name__ == '__main__':
    main()
