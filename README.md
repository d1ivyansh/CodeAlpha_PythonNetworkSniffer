# CodeAlpha_Python Network Sniffer
'Scapy is a powerful Python library used for packet manipulation, sniffing, creation, and network discovery. It allows you to interact with packets at a low level, making it an excellent tool for network engineers, security analysts, and developers.'

Here's how you can create a simple Python network sniffer tool using Scapy

For an Example:

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
            This script defines a packet_callback function that is called whenever a packet is sniffed. It inspects the packet layers using Scapy's haslayer method and prints information about Ethernet frames, ARP packets, IP packets, TCP segments, and UDP datagrams.

1. Importing Modules:                    
from scapy.all import sniff, Ether, ARP, IP, TCP, UDP: This line imports the necessary modules from Scapy, including functions and classes for sniffing packets (sniff) and various protocol layers (Ether, ARP, IP, TCP, UDP).

2. Defining Packet Callback Function:                           
def packet_callback(packet):: This function defines the callback that will be executed for each packet sniffed by Scapy.
if packet.haslayer(Ether):: Checks if the packet has an Ethernet layer.
if packet.haslayer(ARP):: Checks if the packet has an ARP layer.
if packet.haslayer(IP):: Checks if the packet has an IP layer.
Inside each layer check, specific information about the packet is printed based on the protocol type detected (Ether, ARP, IP).
If the packet has an IP layer, further checks are made for TCP and UDP layers, printing information about source and destination ports if present.

3. Sniffing Network Traffic:                                            
sniff(prn=packet_callback, count=10): Initiates packet sniffing using the sniff function from Scapy.
prn=packet_callback: Specifies the callback function to be executed for each packet sniffed.
count=10: Specifies the number of packets to capture. Adjust this parameter as needed.


#To use the script:

1.Install Scapy if you haven't already: pip install scapy.

Copy the script into a Python file (e.g., network_sniffer.py).

2.Run the script with sufficient privileges (e.g., sudo python network_sniffer.py) to allow sniffing network traffic.
Adjust the count parameter in the sniff function to specify the number of packets to capture. You can also specify additional parameters such as filtering criteria, timeout, etc., as needed.

Remember to use caution when running network sniffing tools, especially in production environments, and ensure compliance with applicable laws and regulations.







#Make sure you run this script with root/administrative privileges to capture packets on your network interface.
