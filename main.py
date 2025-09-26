from scapy.all import IP, TCP, UDP, sniff
from datetime import datetime

# -----------------------------
# Configuration
# -----------------------------
suspicious_ips = ["192.168.1.100", "10.0.0.50"]
log_file = "packet_analysis_report.txt"
packet_count = 50  # Number of packets to capture

# -----------------------------
# Logging function
# -----------------------------
def log_event(event):
    """Append events to log file with timestamp and print to console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {event}"
    with open(log_file, "a") as f:
        f.write(log_entry + "\n")
    print(log_entry)

# -----------------------------
# Packet analysis function
# -----------------------------
def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "Other"

        if TCP in packet:
            proto = "TCP"
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN flag
                log_event(f"[!] TCP SYN Scan detected from {src} -> {dst}")
        elif UDP in packet:
            proto = "UDP"

        # Display simplified packet info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} | {proto} | {src} -> {dst}")

        # Suspicious IP check
        if src in suspicious_ips:
            log_event(f"[!] Suspicious Source IP detected: {src} -> {dst}")

# -----------------------------
# Main execution
# -----------------------------
if __name__ == "__main__":
    print(f"Starting packet capture for {packet_count} packets...")
    sniff(prn=analyze_packet, count=packet_count)
    print("Packet capture finished.")
