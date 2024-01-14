from scapy.all import *

def verify_tls(pkt):
    if pkt.haslayer("tls"):
        print("TLS detected in packet:")
        print(pkt.summary())
        #print(pkt.show())


# Capture packets live (replace with 'offline' to analyze a PCAP file):
sniff(prn=verify_tls, filter="tcp port 443", count=1)
