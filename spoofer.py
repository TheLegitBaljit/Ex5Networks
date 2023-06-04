import socket
import struct

seq = 0  # A sequence number for the spoofed TCP packets


def send_raw_ip_packet(ip):
    # Step 1: Create a raw network socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Step 2: Send the packet out
    sock.sendto(ip, (ip['DestIP'], 0))

    # Step 3: Close the socket
    sock.close()


def spoof_icmp(dest):
    # Step 1: Fill in the ICMP header
    icmp = struct.pack('!BBHHH', 8, 0, 0, 0, seq)
    checksum = in_cksum(icmp)

    # Step 2: Fill in the IP header
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 28, 0, 21, socket.IPPROTO_ICMP, 0, socket.htons(0),
                     socket.inet_aton("1.2.3.4"), socket.inet_aton(dest))

    # Step 3: Fill in the packet with ICMP and IP headers
    packet = ip + icmp + struct.pack('!H', checksum)

    # Step 4: Send the spoofed packet
    send_raw_ip_packet(packet)


def spoof_udp(dest, port):
    # Step 1: Fill in the UDP header
    udp = struct.pack('!HHHH', 12345, port, 8 + len("This is a fake packet!\n"), 0)

    # Step 2: Fill in the IP header
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 28 + len("This is a fake packet!\n"), 0, 21, socket.IPPROTO_UDP,
                     0, socket.htons(0), socket.inet_aton("1.2.3.4"), socket.inet_aton(dest))

    # Step 3: Fill in the packet with UDP and IP headers
    packet = ip + udp + "This is a fake packet!\n"

    # Step 4: Send the spoofed packet
    send_raw_ip_packet(packet)


def spoof_tcp(dest, port):
    global seq
    seq += 1

    # Step 1: Fill in the TCP header
    tcp = struct.pack('!HHLLBBHHH', 12345, port, seq, 1, 8, 5, 1000, 0, 0)
    checksum = in_cksum(tcp)

    # Step 2: Fill in the IP header
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 28, 0, 21, socket.IPPROTO_TCP, 0, socket.htons(0),
                     socket.inet_aton("1.2.3.4"), socket.inet_aton(dest))

    # Step 3: Fill in the packet with TCP and IP headers
    packet = ip + tcp + struct.pack('!H', checksum) + "This is a fake packet!\n"

    # Step 4: Send the spoofed packet
    send_raw_ip_packet(packet)


def in_cksum(p):
    n = len(p) % 2
    p = struct.unpack('!' + ('H' * (len(p) // 2)) + ('B' * n), p)

    s = sum(p)
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    s = ~s & 0xffff

    return s


def main():
    while True:
        print("Enter (1) to spoof ICMP packet")
        print("Enter (2) to spoof UDP packet")
        print("Enter (3) to spoof TCP packet")
        print("Enter (0) to exit")
        choice = int(input("Your choice: "))

        if choice == 0:
            break

        elif choice == 1:
            dest = input("Enter IP to send spoofed packet: ")
            spoof_icmp(dest)
            print("(+) Spoofed ICMP packet successfully.")

        elif choice == 2:
            dest = input("Enter IP to send spoofed packet: ")
            port = int(input("Enter port to send spoofed packet: "))
            spoof_udp(dest, port)
            print("(+) Spoofed UDP packet successfully.")

        elif choice == 3:
            dest = input("Enter IP to send spoofed packet: ")
            port = int(input("Enter port to send spoofed packet: "))
            spoof_tcp(dest, port)
            print("(+) Spoofed TCP packet successfully.")

        else:
            print("(-) Invalid input. Try again.")


if __name__ == '__main__':
    main()
