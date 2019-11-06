## About
> These scripts utilize PAN OS api interface on Palo Alto Networks Firewall
to get some information and print on terminal screen in a formatted way.

1. **get_stats.py :** _prints values about resources such as CPU, sessions, buffer etc._

2. **get_session_info.py :** _prints established sessions according to entered
source, destination IP addresses and destination port._

3. **get_arp_table.py :** _prints arp table_
### Screenshots

#### 1. get_stats.py
> resource status function output:

![resource status function output](./resource_status_info.png)

> CPUs, sessions, buffer utilization function enabled output:

![CPUs, sessions status output](./utilization.png)

#### 2. get_session_info.py

_A file named "last_sessions_file.txt" is saved to the same directory. 
To sort with respect to bytes column in bash shell:_
```Shell
$ grep " M " last_sessions_file.txt | tr -s ' ' | sort -k7 -n
```
> any sessions output:

![any sessions output](./get_session_info.png)

