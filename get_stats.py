#!/usr/bin/env pythons
"""Retrieves some system stats-metrics values from
Palo Alto Networks Firewall utilizing
PAN OS api interface.

"""
import requests
import xmltodict
import re
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


def get_zone_protection_metrics():
    querystring = {"type":"op",
                   "cmd":"<show><zone-protection><zone>OUTSIDE</zone></zone-protection></show>",
                   "key":PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)

    response_dict = xmltodict.parse(response.text, dict_constructor=dict)

    outside_metrics_dict = response_dict['response']['result']['entries']['entry']
    return outside_metrics_dict


def get_sessions_stats():
    querystring = {"type":"op",
                   "cmd":"<show><session><info></info></session></show>",
                   "key":PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)

    response_dict = xmltodict.parse(response.text, dict_constructor=dict)

    session_metrics_dict = response_dict['response']['result']
    return session_metrics_dict


def get_cpu_stats():
    querystring = {"type": "op",
                   "cmd": "<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>",
                   "key":PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)

    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    cpu_metrics_dict = response_dict['response']['result']['resource-monitor']['data-processors']
    return cpu_metrics_dict


def get_mgmt_cpu():
    querystring = {"type": "op",
                   "cmd": "<show><system><resources></resources></system></show>",
                   "key":PANOS_API_TOKEN}

    response = requests.request("GET", url, params=querystring, verify=False)

    response_dict = xmltodict.parse(response.text, dict_constructor=dict)
    mgmt_cpu_str = response_dict['response']['result']
    result = re.search(r"load average: (.+?),", mgmt_cpu_str)  # 1 minute average in top output
    return result.group(1)

# PRINT FUNCTIONS


def print_sessions_stats():
    sessions_dict = get_sessions_stats()
    num_of_tcp_sessions = sessions_dict['num-tcp']
    num_of_udp_sessions = sessions_dict['num-udp']
    num_of_icmp_sessions = sessions_dict['num-icmp']
    total_sessions = sessions_dict['num-active']
    new_connection_rate = sessions_dict['cps']
    throughput = sessions_dict['kbps']
    packet_rate = sessions_dict['pps']

    print(colors.bold + colors.fg.orange + colors.underline + "General Resource Status Info" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("TCP Sessions in Use", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(num_of_tcp_sessions) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("UDP Sessions in Use", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(num_of_udp_sessions) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("ICMP Sessions in Use", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(num_of_icmp_sessions) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Total Sessions in Use", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(total_sessions) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("New Connections Rate", ":") + colors.reset
          + colors.fg.green + "{:>10} cps".format(new_connection_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Firewall Throughput Rate", ":") + colors.reset
          + colors.fg.green + "{:>10} {}".format(throughput if int(throughput) < 1024 else round(int(throughput) / 1024, 3)
                                                 , "Kbps" if int(throughput) < 1024 else "Mbps") + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Firewall Packet Rate", ":") + colors.reset
          + colors.fg.green + "{:>10} {}".format(packet_rate if int(packet_rate) < 1024 else round(int(packet_rate) / 1024, 3)
                                                 , "pps" if int(packet_rate) < 1024 else "Kpps") + colors.reset)
    print("-" * 52)


def print_cpu_stats():
    cpu_dict = get_cpu_stats()
    dp0_values_total = 0
    dp0_core_avg_values = cpu_dict['dp0']['minute']['cpu-load-average']['entry']
    for coreid_value_dict in dp0_core_avg_values:
        if coreid_value_dict['coreid'] != '0':
            dp0_values_total += int(coreid_value_dict['value'])
        if coreid_value_dict['coreid'] == '1':
            dp0_session_flow_core_value = int(coreid_value_dict['value'])

    dp1_values_total = 0
    dp1_core_avg_values = cpu_dict['dp1']['minute']['cpu-load-average']['entry']
    for coreid_value_dict in dp1_core_avg_values:
        if coreid_value_dict['coreid'] != '0':
            dp1_values_total += int(coreid_value_dict['value'])
        if coreid_value_dict['coreid'] == '1':
            dp1_session_flow_core_value = int(coreid_value_dict['value'])

    data_plane_cpu_avg = round((dp0_values_total + dp1_values_total) / 22)
    session_flow_cpu_avg = round((dp0_session_flow_core_value + dp1_session_flow_core_value) / 2)

    sys_cpu = float(get_mgmt_cpu())

    print(colors.bold + colors.fg.orange + "Palo Alto System Stats for Last 1 Minute:" + colors.reset)

    print(colors.bold + colors.fg.orange + colors.underline + "CPU Utilization" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Data Plane CPU Average", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(data_plane_cpu_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Session-Flow CPU Average", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(session_flow_cpu_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Mgmt Plane CPU Average", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(str(round((session_flow_cpu_avg + sys_cpu) / 2, 2)))
          + colors.reset)

    dp0_resource_util_avg_values = cpu_dict['dp0']['minute']['resource-utilization']['entry']
    for resource_util_avg_val in dp0_resource_util_avg_values:
        if resource_util_avg_val['name'] == 'session (average)':
            dp0_session_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'session (maximum)':
            dp0_session_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet buffer (average)':
            dp0_pkt_buf_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet buffer (maximum)':
            dp0_pkt_buf_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (average)':
            dp0_pkt_desc_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (maximum)':
            dp0_pkt_desc_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (on-chip) (average)':
            dp0_pkt_desc_chip_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (on-chip) (maximum)':
            dp0_pkt_desc_chip_max = int(resource_util_avg_val['value'])

    dp1_resource_util_avg_values = cpu_dict['dp1']['minute']['resource-utilization']['entry']
    for resource_util_avg_val in dp1_resource_util_avg_values:
        if resource_util_avg_val['name'] == 'session (average)':
            dp1_session_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'session (maximum)':
            dp1_session_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet buffer (average)':
            dp1_pkt_buf_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet buffer (maximum)':
            dp1_pkt_buf_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (average)':
            dp1_pkt_desc_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (maximum)':
            dp1_pkt_desc_max = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (on-chip) (average)':
            dp1_pkt_desc_chip_avg = int(resource_util_avg_val['value'])
        elif resource_util_avg_val['name'] == 'packet descriptor (on-chip) (maximum)':
            dp1_pkt_desc_chip_max = int(resource_util_avg_val['value'])

    print("-" * 52)

    print(colors.bold + colors.fg.orange + colors.underline + "Resource Utilization for Sessions" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_session_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_session_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_session_max) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_session_max) + colors.reset)

    print(colors.bold + colors.fg.orange + colors.underline + "Resource Utilization for Packet Buffer" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_buf_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_buf_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_buf_max) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_buf_max) + colors.reset)

    print(
        colors.bold + colors.fg.orange + colors.underline + "Resource Utilization for Packet Descriptor" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_desc_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_desc_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_desc_max) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_desc_max) + colors.reset)

    print(colors.bold + colors.fg.orange + colors.underline + "Resource Utilization for Packet Descriptor (On-Chip)"
          + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_desc_chip_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Average on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_desc_chip_avg) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp0", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp0_pkt_desc_chip_max) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Maximum on dp1", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(dp1_pkt_desc_chip_max) + colors.reset)
    print("-" * 52)


def print_zone_protection():
    zone_protection_dict = get_zone_protection_metrics()
    zone = zone_protection_dict['zone']
    tcp_syn_dict = zone_protection_dict['tcp-syn']
    tcp_assured_set_value = tcp_syn_dict['assured']
    tcp_maximum_set_value = tcp_syn_dict['maximum']
    current_tcp_syns = tcp_syn_dict['current']
    dropped_tcp_syn = tcp_syn_dict['stats']

    print(colors.bold + colors.fg.orange + colors.underline + "Zone Protection Status Info for {}".format(zone)
          + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("TCP Assured Set Value", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_assured_set_value) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("TCP Maximum Set Value", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_maximum_set_value) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Current Number of SYNs", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(current_tcp_syns) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Dropped TCP SYNs", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(dropped_tcp_syn) + colors.reset)
    print("-" * 52)


def main():
#    print_cpu_stats()
    print_sessions_stats()
#    print_zone_protection()


if __name__ == "__main__":
    main()
