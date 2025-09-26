from scapy.all import IP, TCP, sniff

# List of suspicious IPs
suspicious_ips = ["192.168.1.100", "10.0.0.50"]

def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        # Check for suspicious source IP
        if src in suspicious_ips:
            print(f"[!] Suspicious Source IP detected: {src}")

        # Check for TCP SYN scan attempt
        if TCP in packet and packet[TCP].flags == "S":
            print(f"[!] TCP SYN Scan attempt from {src} to {dst}")

# Capture 50 packets
sniff(prn=analyze_packet, count=50)
