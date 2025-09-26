from scapy.all import sniff

def packet_capture(packet):
    print(packet.summary())

# Capture 50 packets
sniff(count=50, prn=packet_capture)
