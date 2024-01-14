from scapy.all import *

def is_tls_packet(packet):
    return packet.haslayer(TCP) and packet.haslayer(Raw) and b'\x16\x03\x01' in packet[Raw].load

def packet_callback(packet):
    if is_tls_packet(packet):
        print("TLS packet found:")
        print(packet.summary())
        print(packet.show())

# Sniffing for packets and calling the packet_callback for each packet
sniff(prn=packet_callback, store=0, filter="tcp port 443")  # Adjust the filter as needed
