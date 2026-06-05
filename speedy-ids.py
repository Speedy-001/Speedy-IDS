#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time

# Track packets per IP
ip_counts = defaultdict(lambda: {'SYN': 0, 'ICMP': 0, 'ports': set(), 'time': time.time()})

def packet_handler(packet):
    if IP in packet:
        ip_src = packet[IP].src
        now = time.time()
        
        # Reset counters every 10 seconds
        if now - ip_counts[ip_src]['time'] > 10:
            ip_counts[ip_src] = {'SYN': 0, 'ICMP': 0, 'ports': set(), 'time': now}
        
        # Detect SYN flood
        if TCP in packet and packet[TCP].flags == 'S':
            ip_counts[ip_src]['SYN'] += 1
            if ip_counts[ip_src]['SYN'] > 100:
                print(f"[ALERT] Possible SYN Flood from {ip_src}")
        
        # Detect ICMP flood
        if ICMP in packet:
            ip_counts[ip_src]['ICMP'] += 1
            if ip_counts[ip_src]['ICMP'] > 50:
                print(f"[ALERT] Possible ICMP flood from {ip_src}")
                
        # Detect Port Scan (Tracks unique ports visited in the 10s window)
        if TCP in packet and packet[TCP].dport in range(1, 1001):
            ip_counts[ip_src]['ports'].add(packet[TCP].dport)
            if len(ip_counts[ip_src]['ports']) > 20:  # Triggers if >20 distinct ports are probed
                print(f"[ALERT] Port scan detected from {ip_src} (Probed {len(ip_counts[ip_src]['ports'])} ports)")

print("[*] Starting IDS. Press Ctrl+C to stop.")
sniff(prn=packet_handler, store=0)