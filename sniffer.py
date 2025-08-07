
# sniffer.py
from scapy.all import sniff, IP, TCP
from collections import defaultdict
from rich.console import Console
import netifaces
import time
import os

# Setup
console = Console()
syn_tracker = defaultdict(list)
SYN_THRESHOLD = 20
TIME_WINDOW = 10

# Create log directory
os.makedirs("logs", exist_ok=True)
LOG_FILE = "logs/alerts.log"

def log_alert(alert_msg):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {alert_msg}\n")

def get_default_interface():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][1]

def process_packet(packet):
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src = ip_layer.src
        dst = ip_layer.dst
        dport = tcp_layer.dport
        flags = tcp_layer.flags

        if flags == 'S':  # SYN Packet
            now = time.time()
            syn_tracker[src].append((now, dport))
            syn_tracker[src] = [(t, p) for t, p in syn_tracker[src] if now - t < TIME_WINDOW]

            unique_ports = set(p for t, p in syn_tracker[src])

            if len(unique_ports) > SYN_THRESHOLD:
                alert_msg = f"[ALERT] Port scan detected from {src} — tried {len(unique_ports)} ports in {TIME_WINDOW} seconds!"
                console.print(alert_msg, style="bold red")
                log_alert(alert_msg)
                syn_tracker[src] = []  # Reset
        else:
            msg = f"{src} -> {dst} | Port: {dport} | Flags: {flags}"
            console.print(msg, style="dim")

if __name__ == "__main__":
    iface = get_default_interface()
    console.print(f"[*] Sniffing on interface: {iface}", style="bold green")
    sniff(iface=iface, prn=process_packet, store=False, count=100)



#protocol: 6 -> TCP
#protocol: 17 -> UDP
#scapy basically sniffs packets and manipulate packets
#netifaces-> decides on the network interfaces (wifi)
#defaultdict to store data per IP.
#def interfaces()->figures out how to cahieve network interfaces using your routing table
#def process_packet() -> a callback function that is called every time a new packet arrives, it print src ip, dest ip, and protocol number.
#in syn_tracker[src] , we are just deleting the old activities and considering only the new activities withing the timelimit
# we are also setting the sync threshhold to 20 , so if it exceeds 20 diff ports withing 10 seconds then more likely a port scan and it will raise an alert.

