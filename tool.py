from scapy.all import sniff, Ether, ARP, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(Ether):
        print("Ethernet Frame:")
        print(f"Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

    if packet.haslayer(ARP):
        print("ARP Packet:")
        print(packet.summary())

    if packet.haslayer(IP):
        print("IP Packet:")
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("TCP Segment:")
            print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

        if packet.haslayer(UDP):
            print("UDP Datagram:")
            print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

# Sniffing network traffic
sniff(prn=packet_callback, count=10)  # Adjust count as needed



