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

- # Install dependencies
- pip install scapy
- # main.py
- Acts as the entry point of the project.
- Configures suspicious IPs, log file, and packet capture count.
- Contains log_event() to record suspicious activities both in the console and a report file.
- Contains analyze_packet() to process each packet:
-      Detects TCP SYN scans.
-      Identifies suspicious source IPs.
-      Displays basic packet details (protocol, source, destination).
-  Starts live packet capture using scapy.sniff() and stops after capturing the configured number of packets.
