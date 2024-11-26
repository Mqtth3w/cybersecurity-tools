'''
@author Mqtth3w https://github.com/mqtth3w
@license GPL-3.0
'''
from scapy.all import *
import socket
import whois
from ipwhois import IPWhois

def get_ip_details(ip):
    details = {}
    try:
        details['domain'] = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        details['domain'] = "No domain found"
    try:
        ip_whois = IPWhois(ip)
        whois_result = ip_whois.lookup_rdap()
        details['owner'] = whois_result.get("network", {}).get("name", "Unknown owner")
        details['asn'] = whois_result.get("asn", "Unknown ASN")
        details['asn_desc'] = whois_result.get("asn_description", "Unknown ASN description")
        details['country'] = whois_result.get("network", {}).get("country", "Unknown country")
    except Exception:
        details.update({'owner': 'Error retrieving info', 'asn': '-', 'asn_desc': '-', 'country': '-'})
    return details

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
        print(f"Packet: {src_ip} --> {dst_ip} | Protocol: {proto_name}")
        ip_info = get_ip_details(dst_ip)
        print(f"    Domain: {ip_info['domain']}")
        print(f"    Owner: {ip_info['owner']}")
        print(f"    ASN: {ip_info['asn']} ({ip_info['asn_desc']})")
        print(f"    Country: {ip_info['country']}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            print(f"    Source Port: {sport}, Destination Port: {dport}")
        print(packet.show())
        if packet.haslayer(Raw):
            print("Raw Data:")
            print(packet[Raw].load.hex())
        print("=" * 60)

def start_sniffing():
    print("Starting packet sniffing. Press Ctrl+C to stop.")
    sniff(iface=None, prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
