from scapy.all import *

# Funzione per catturare e analizzare i pacchetti di rete
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Packet: {src_ip} --> {dst_ip}")
        
        # Stampa dettagliata del pacchetto
        print(packet.show())
        
        # Stampa il contenuto "Raw" del pacchetto
        if packet.haslayer(Raw):
            print("Raw Data:")
            print(packet[Raw].load.hex())  # Stampa il contenuto "Raw" come esadecimale
            
        print("=" * 50)  # Linea di separazione tra pacchetti

# Avvia la cattura dei pacchetti in tempo reale
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
