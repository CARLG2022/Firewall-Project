import os
from scapy.all import *
from datetime import datetime 

LOG_FILE= "firewall_log.txt"
BLOCKED_IPS = set()  # Keeps track of blocked IPs to prevent duplicating 

# Function to log activity
def log_activity(ip, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current time
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] [BLOCKED] {ip} - {reason}\n")
        log.write(f"[{timestamp}] [BLOCKED] {ip} - Blocked due to suspicious activity\n")
    print(f"[LOGGED] {ip} - {reason}")

# Function to block an attacker's IP using iptables
def block_ip(ip, reason):
    if ip not in BLOCKED_IPS:  # Only block and log once per IP
        print(f"[ALERT] Blocking traffic from {ip} - {reason}")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        log_activity(ip, reason)  # Log only once
        BLOCKED_IPS.add(ip)  # Keep track of blocked IPs
    else:
        print(f"[ALERT] {ip} is already blocked. No duplicate logging.")
    

# Function to detect and block Nmap scans
def detect_nmap(packet):
    if packet.haslayer(TCP):
        attacker_ip = packet[IP].src
        
        # Stop processing if the IP is already blocked
        if attacker_ip in BLOCKED_IPS:
            return  

        if packet[TCP].flags == "S":  # SYN packets (used in Nmap scans)
            print(f"[ALERT] Possible Nmap scan detected from {attacker_ip}")
            block_ip(attacker_ip, "Nmap scan detected")


# Function to detect and block ICMP (Ping) packets
def detect_icmp(packet):
    if packet.haslayer(ICMP):
        attacker_ip = packet[IP].src
        # Stop processing if the IP is already blocked
        if attacker_ip in BLOCKED_IPS:
            return  
        print(f"[ALERT] Ping detected from {attacker_ip} - Possible reconnaissance attempt.")
        block_ip(attacker_ip, "Ping detected")  # Pass reason to block_ip()


# Function to process incoming packets
def process_packet(packet):
    detect_nmap(packet)
    detect_icmp(packet)

# Start sniffing packets on eth0
print("Firewall running... Monitoring for scans and pings")
sniff(iface="eth0", filter="ip", prn=process_packet, store=0)
