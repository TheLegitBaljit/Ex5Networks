from scapy.all import *

def spoof_icmp(src_ip, dst_ip):
    # Craft an ICMP packet with spoofed source IP
    packet = IP(src=src_ip, dst=dst_ip) / ICMP()
    
    # Send the packet
    send(packet)
    print("Spoofed ICMP packet sent.")

def spoof_udp(src_ip, src_port, dst_ip, dst_port):
    # Craft a UDP packet with spoofed source IP and port
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
    
    # Send the packet
    send(packet)
    print("Spoofed UDP packet sent.")

def spoof_tcp(src_ip, src_port, dst_ip, dst_port):
    # Craft a TCP packet with spoofed source IP and port
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
    
    # Send the packet
    send(packet)
    print("Spoofed TCP packet sent.")

# Example usage
source_ip = "1.2.3.4"
destination_ip = "10.9.0.5"

# Spoof ICMP packet
spoof_icmp(source_ip, destination_ip)

# Spoof UDP packet
source_port = 12345
destination_port = 80
spoof_udp(source_ip, source_port, destination_ip, destination_port)

# Spoof TCP packet
spoof_tcp(source_ip, source_port, destination_ip, destination_port)
