'''
    @author Matteo Gianvenuti https://github.com/mqtth3w
    @license MIT License
'''

from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Packet: {src_ip} --> {dst_ip}")
        print(packet.show())
        if packet.haslayer(Raw):
            print("Raw Data:")
            print(packet[Raw].load.hex())
        print("=" * 60)

def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
