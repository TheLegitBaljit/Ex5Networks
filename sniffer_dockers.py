from scapy.all import *
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now()
    source_port = None  # Initialize as None
    dest_port = None  # Initialize as None
    cache_flag = None
    steps_flag = None
    type_flag = None
    status_code = None
    cache_control = None
    
    if ICMP in packet:
        proto = "ICMP"
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        total_length = packet[IP].len
        
    elif TCP in packet:
        proto = "TCP"
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        total_length = packet[IP].len

    elif UDP in packet:
        proto = "UDP"
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport
        total_length = packet[IP].len

    elif IGMP in packet:
        proto = "IGMP"
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        total_length = packet[IP].len

    else:
        proto = "RAW"
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        total_length = packet[IP].len


    data = bytes(packet).hex()  # Converts packet data to hexadecimal

    with open('output.txt', 'a') as f:
            f.write(f'source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port}, timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, steps_flag: {steps_flag}, type_flag: {type_flag}, status_code: {status_code}, cache_control: {cache_control}, data: {data}\n')

sniff(prn=packet_callback, filter="ip", store=0,iface='br-3d043327ca9d')

