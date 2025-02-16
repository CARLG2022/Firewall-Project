# Intrusion Detection Firewall
## Overview
This Python-based intrusion detection system (IDS) monitors incoming network traffic for Nmap scans and ICMP (ping) packets. The script uses Scapy to sniff network packets, detect suspicious activity, and automatically block the attacker's IP using iptables.
## Features
* Detects and blocks Nmap scans (SYN packets)
* Identifies ICMP (ping) reconnaissance attempts
* Automatically blocks attackers' IP addresses using iptables
* Logs all blocked IPs in firewall_log.txt
## Prerequisites
Before running the script, ensure you have:
* Python 3.x installed
* Scapy (pip install scapy)
* Root (sudo) privileges (required for modifying firewall rules)
## Installation and Usage 
1. Clone the repository:
```
https://github.com/CARLG2022/Firewall-Project.git
cd firewall_project
```
2. Running the Script:
```
sudo python3 firewall.py
```
3. Example Output:
```
Firewall running... Monitoring for scans and pings

[ALERT] Possible Nmap scan detected from 192.168.1.50
[ALERT] Blocking traffic from 192.168.1.50 - Nmap scan detected
[LOGGED] 192.168.1.50 - Nmap scan detected

[ALERT] Ping detected from 203.0.113.10 - Possible reconnaissance attempt.
[ALERT] Blocking traffic from 203.0.113.10 - Ping detected
[LOGGED] 203.0.113.10 - Ping detected
```
## License
This project is licensed under the MIT License.
