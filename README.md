# Packet_Analysis_Tool

📌 Introduction

This project is a **Packet Analysis Tool** developed in Python using **Scapy**.  
It captures live network packets, analyzes them, and helps identify **suspicious activity** such as malicious IPs, unusual traffic patterns, or potential attacks.  
The tool is designed as a **Cyber Security mini project** to demonstrate real-time packet sniffing and analysis.


✨ Features

- Capture live network traffic
- Display essential packet details (Source IP, Destination IP, Protocol, Timestamp)
- Detect suspicious IPs or patterns
- Identify potential threats such as DoS/DDoS, malicious packets, etc.
- Simple and lightweight command-line interface

 # Install dependencies
-        pip install scapy
 # main.py
- Acts as the entry point of the project.
- Configures suspicious IPs, log file, and packet capture count.
- Contains log_event() to record suspicious activities both in the console and a report file.
- Contains analyze_packet() to process each packet:
-- Detects TCP SYN scans.
-- Identifies suspicious source IPs.
--  Displays basic packet details (protocol, source, destination).
-  Starts live packet capture using scapy.sniff() and stops after capturing the configured number of packets.

  # packet_capture.py
-  Responsible for capturing live packets from the network.
-  Uses scapy.sniff() to capture 50 packets by default.
-  Defines packet_capture() function that prints a short summary of each packet as it is captured.
-  Works as a standalone module for basic packet sniffing.

# packet_analysis.py
- Focuses on analyzing captured packets.
- Defiine a list of suspicious IPs to monitor.
- analyze_packet() function checks each packet:
-- Flags suspicious source IPs.
-- Detects TCP SYN scan attempts (possible port scan activity).
- Uses scapy.sniff() to capture 50 packets and analyze them in real-time.
