# Personal-Firewall-using-Python

# Objective
Develop a lightweight, rule-based personal firewall using Python that can monitor and filter network traffic, log suspicious activity, and optionally integrate with system-level firewall tools like iptables on Kali Linux.

# Tools & Technologies
Component	Tool / Library
Language	Python 3.x
Packet Sniffing	Scapy
System Firewall	iptables (Linux native)
Platform	Kali Linux (Debian-based)

# Project Structure
personal-firewall/
│
├── firewall.py           # Main logic: sniffing + filtering
├── rules.json            # JSON file with allow/block rules
├── logger.py             # Logging functionality
├── iptables_utils.py     # (Optional) iptables integration
├── requirements.txt      # Python dependencies
└── README.md             # Documentation (this file)

# Step-by-Step Project Development

Step 1: Setup Environment on Kali Linux
Install Python and Dependencies:
sudo apt update && sudo apt upgrade -y

<img width="1007" height="371" alt="image" src="https://github.com/user-attachments/assets/9316164d-4994-4ac7-bc03-c81e9d2aecdf" />

sudo apt install python3 python3-pip -y
pip3 install scapy

<img width="1220" height="499" alt="image" src="https://github.com/user-attachments/assets/8629b1d2-7b14-4fa0-a244-f66206b7c0b1" />


Step 2: Create the Project Structure
mkdir personal-firewall
cd personal-firewall
touch firewall.py logger.py iptables_utils.py rules.json requirements.txt

<img width="709" height="95" alt="image" src="https://github.com/user-attachments/assets/894b0ef3-9754-4a38-9d57-dc51b91afc8f" />


Step 3: Define Rules in rules.json
This file controls which IPs, ports, or protocols to allow or block.
Open rules.json in a text editor:
nano rules.json
Code:
json
{
  "block": {
    "ip": ["192.168.1.100"],
    "port": [80, 443],
    "protocol": ["TCP"]
  },
  "allow": {
    "ip": ["127.0.0.1"],
    "port": [22],
    "protocol": ["ICMP"]
  }
}

<img width="984" height="268" alt="image" src="https://github.com/user-attachments/assets/a75d2cb1-8e0a-4505-933a-b682f270e6a9" />


Step 4: Create Logger Script logger.py
Open logger.py:
nano logger.py

Code:
python
import logging

# Configure logging to file
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def log_packet(packet, reason):
    summary = packet.summary()
    logging.info(f"{summary} - {reason}")

<img width="1119" height="256" alt="image" src="https://github.com/user-attachments/assets/d676141d-7b79-4067-a077-3b2bd476cff8" />

    
Step 5: Create Main Firewall Logic in firewall.py
This script uses Scapy to sniff packets and filters them.

Open firewall.py:
nano firewall.py

Code:
from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from logger import log_packet

# Load rules from JSON file
with open('rules.json') as f:
    rules = json.load(f)

def check_packet(pkt):
  if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "OTHER"
        port = None

   # Determine protocol and port
   if TCP in pkt:
            proto = "TCP"
            port = pkt[TCP].sport
        elif UDP in pkt:
            proto = "UDP"
            port = pkt[UDP].sport
        elif ICMP in pkt:
            proto = "ICMP"

   # Apply blocking rules
   if (src_ip in rules["block"]["ip"]) or \
           (port in rules["block"]["port"] if port else False) or \
           (proto in rules["block"]["protocol"]):

   print(f"[BLOCKED] {src_ip}:{port} ({proto}) -> {dst_ip}")
            log_packet(pkt, "Blocked")
   else:
        print(f"[ALLOWED] {src_ip}:{port} ({proto}) -> {dst_ip}")

print("[+] Starting firewall packet sniffing...")
sniff(prn=check_packet, store=0)

<img width="1262" height="652" alt="image" src="https://github.com/user-attachments/assets/2669ec3c-3f77-406e-a269-9dd9828899c9" />


Step 6: Run the Firewall
Make sure you’re in the personal-firewall directory:
cd ~/personal-firewall

Run with sudo (required by Scapy):
sudo python3 firewall.py

<img width="1045" height="657" alt="image" src="https://github.com/user-attachments/assets/c0975152-3f64-438e-a56d-979de7684f44" />


Step 7 Integrate with iptables
iptables_utils.py lets you block IPs directly at the kernel level.

Open the file:
nano iptables_utils.py

Code:
import subprocess

def block_ip(ip):
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd)
    print(f"[iptables] Blocked {ip}")

<img width="1031" height="238" alt="image" src="https://github.com/user-attachments/assets/52cf39f8-d7c9-436b-9a2b-6062f4ea1a99" />

Final Checklist

Task	                       Status

Python environment ready	    ✅

rules.json created	          ✅

Packet sniffing implemented	  ✅

Logging in place	            ✅

iptables optional support	    ✅

Runs on Kali with sudo	      ✅


