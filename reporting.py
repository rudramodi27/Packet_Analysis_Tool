from datetime import datetime

# Reporting file ka naam
log_file = "packet_analysis_report.txt"

def log_event(event):
    """Log events to a text file with timestamp."""
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} - {event}\n")

# Example usage
log_event("[!] Suspicious IP detected: 192.168.1.100")
log_event("[!] TCP SYN Scan attempt from 10.0.0.50 to 192.168.1.20")
