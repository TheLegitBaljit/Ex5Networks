from scapy.all import *

def traceroute(destination):
    ttl = 1
    max_hops = 100

    while True:
        # Create the packet with increasing TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()

        # Send the packet and receive the response
        reply = sr1(packet, verbose=False, timeout=1)

        if reply is None:
            # No reply received, print timeout message
            print(f"{ttl}. No reply")
        elif reply.type == 0:
            # ICMP Echo Reply received, print the destination reached message
            print(f"{ttl}. {reply.src}  Destination Reached!")
            break
        else:
            # ICMP Time Exceeded error received, print the router IP
            print(f"{ttl}. {reply.src}")

        ttl += 1

        if ttl > max_hops:
            # Maximum number of hops reached, exit the loop
            break

# Example usage
traceroute("www.facebook.com")