from scapy.all import *
import inspect
print("____________________OSI Model____________________\n")
print(
"""
┌─────────────────────────────────────────────┐
│  7. Application     (HTTP, DNS, DHCP)       │  ← User Interface
├─────────────────────────────────────────────┤
│  6. Presentation    (Encryption, Compress.) │  ← Data Formatting
├─────────────────────────────────────────────┤
│  5. Session         (Connection Mgmt.)      │  ← Sessions & Ports
├─────────────────────────────────────────────┤
│  4. Transport       (TCP, UDP)              │  ← End-to-End Delivery
├─────────────────────────────────────────────┤
│  3. Network         (IP, ICMP)              │  ← Routing & Addressing
├─────────────────────────────────────────────┤
│  2. Data Link       (Ethernet, ARP)         │  ← Framing & MAC
├─────────────────────────────────────────────┤
│  1. Physical        (Cables, Signals)       │  ← Raw Bit Transmission
└─────────────────────────────────────────────┘
"""
)

print("\n___________________Scapy Cheat Sheet____________________\n")
print("\n======IP======\n")
print("IP components\n______________\n")

print(ls(IP))

print("\n______________Fragment Flags______________\n")

print("Bit 0 - Reserved (must be zero)")
print("Bit 1 - Don't Fragment (DF)")
print("Bit 2 - More Fragments (MF)")

print("\n______________IP Options______________\n")
print(inspect.signature(IP))

print("\n_____________How to make first packet______________\n")

packet = IP(dst="8.8.8.8", src="192.178.9.0", ttl=64, flags="DF")/ICMP()
print("____show of the packet____")
print(packet.show())
print("\n____summary of the packet____")
print(packet.summary())

print("\n======TCP======\n")
print("TCP components\n______________\n")
print(ls(TCP))

print("\n_____________TCP Flags______________\n")
print("Bit 0 - FIN (Finish) -> (F)")
print("Bit 1 - SYN (Synchronize) -> (S)")
print("Bit 2 - RST (Reset) -> (R)")
print("Bit 3 - PSH (Push) -> (P)")
print("Bit 4 - ACK (Acknowledgment) -> (A)")
print("Bit 5 - URG (Urgent) -> (U)")

print("\n_____________TCP Options______________\n")
print(inspect.signature(TCP))

print("\n_____________How to make first TCP segment______________\n")
segment = IP(dst="8.8.8.8", src="192.168.1.98", ttl=64, flags="DF")/TCP(dport=80, sport=12345, flags="S")

print("____show of the segment____")
print(segment.show())

print("\n____summary of the segment____")
print(segment.summary())

print("\n======UDP======\n")
print("UDP components\n______________\n")
print(ls(UDP))

print("\n_____________UDP Options______________\n")
print(inspect.signature(UDP))

print("\n_____________How to make first UDP datagram______________\n")
datagram = IP(dst="8.8.8.8", src="192.168.1.200", ttl=64, flags="DF")/UDP(dport=53, sport=12345)

print("____show of the datagram____")
print(datagram.show())

print("\n____summary of the datagram____")
print(datagram.summary())

print("\n======ICMP======\n")
print("ICMP components\n______________\n")
print(ls(ICMP))

print("\n_____________ICMP Types______________\n")
print("Type 0 - Echo Reply")
print("Type 3 - Destination Unreachable")
print("Type 4 - Source Quench")
print("Type 5 - Redirect")
print("Type 8 - Echo Request")
print("Type 11 - Time Exceeded")
print("Type 12 - Parameter Problem")

print ("\n_____________ICMP Codes______________\n")
print("Type 3 - Destination Unreachable")
print("Code 0 - Network Unreachable")
print("Code 1 - Host Unreachable")
print("Code 2 - Protocol Unreachable")
print("Code 3 - Port Unreachable")

print("\n_____________ICMP Options______________\n")
print(inspect.signature(ICMP))

print("\n_____________How to make first ICMP packet______________\n")
packet = IP(dst="8.8.8.8")/ICMP(type=8, code=0)

print("____show of the packet____")
print(packet.show())

print("\n____summary of the packet____")
print(packet.summary())

print("\n======Ethernet======\n")
print("Ethernet components\n______________\n")
print(ls(Ether))

print("\n_____________Ethernet Options______________\n")
print(inspect.signature(Ether))

print("\n_____________How to make first Ethernet frame______________\n")
frame = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)/IP(dst="8.8.8.8")/ICMP()

print("____show of the frame____")
print(frame.show())

print("\n____summary of the frame____")
print(frame.summary())

print("\n======ARP======\n")
print("ARP components\n______________\n")
print(ls(ARP))

print("\n_____________ARP Fields Explanation______________\n")
print("hwtype  - Hardware Type (1 = Ethernet 10Mb)")
print("ptype   - Protocol Type (2048 = IPv4)")
print("hwlen   - Hardware Address Length (auto = 6 for MAC)")
print("plen    - Protocol Address Length (auto = 4 for IPv4)")
print("op      - Operation (1 = who-has/Request, 2 = is-at/Reply)")
print("hwsrc   - Source Hardware Address (MAC)")
print("psrc    - Source Protocol Address (IP)")
print("hwdst   - Destination Hardware Address (MAC)")
print("pdst    - Destination Protocol Address (IP)")

print("\n_____________ARP Operations______________\n")
print("op 1  - who-has (ARP Request)")
print("op 2  - is-at (ARP Reply)")

print("\n_____________ARP Options______________\n")
print(inspect.signature(ARP))

print("\n_____________How to make first ARP frame______________\n")
frame = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0806)/ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", hwdst="00:00:00:00:00:00", pdst="192.168.1.2")

print("____show of the frame____")
print(frame.show())

print("\n____summary of the frame____")
print(frame.summary())


print("\n======Sending and Receiving======\n")

print("____Layer 2 (Data Link Layer)____\n")

print("sendp(frame) - send frame at layer 2 (Data Link Layer)\n")

print("srp(frame) - send and receive frame at layer 2 (Data Link Layer)\n")

print("srp1(frame) - send and receive one frame at layer 2 (Data Link Layer)\n")

print("____Layer 3 (Network Layer)____\n")

print("send(packet) - send packet at layer 3 (Network Layer)\n")

print("sr(packet) - send and receive packet at layer 3 (Network Layer)\n")

print("sr1(packet) - send and receive one packet at layer 3 (Network Layer)")
