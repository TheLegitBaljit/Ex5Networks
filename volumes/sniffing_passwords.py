from scapy.all import *

# Define a callback function that prints the source and destination IP addresses
# and the telnet username and password if found in the packet data
def packet_callback(packet):
    # Check if the packet contains IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Get the source and destination IP addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Get the TCP payload (data)
        data = str(packet[TCP].payload)
        # Look for specific patterns indicating a login attempt
        if 'username' in data.lower() or 'password' in data.lower():
            print(f"[*] Source: {ip_src} -> Destination: {ip_dst}")
            packet.show()

sniff(iface="br-027dd95f64fa", filter="tcp port 23", prn=packet_callback)
