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

print("\n======Raw (Raw Payload)======\n")
print("Raw components\n______________\n")
print(ls(Raw))

print("\n_____________Raw Fields Explanation (Important)______________\n")
print("load  - Raw payload data (can be bytes or string)")
print("_____________Raw Usage______________\n")
print("Used to add arbitrary raw data to packets, create malformed packets,")
print("or when Scapy does not recognize the upper layer payload.")

print("\n_____________Raw Options______________\n")
print(inspect.signature(Raw))

print("\n_____________How to make first Raw packet______________\n")
packet = IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print("____show of the packet____")
print(packet.show())

print("\n____summary of the packet____")
print(packet.summary())

print("\n======DNS (Domain Name System)======\n")
print("DNS components\n______________\n")
print(ls(DNS))

print("\n_____________DNS Fields Explanation (Important)______________\n")
print("qr     - Query/Response (0 = Query, 1 = Response)")
print("opcode - Operation code (0 = Standard query)")
print("rd     - Recursion Desired (1 = asks server to fully resolve)")
print("ra     - Recursion Available (1 = server supports recursion)")
print("qdcount- Number of question entries")
print("ancount- Number of answer resource records")
print("nscount- Number of authority resource records")
print("arcount- Number of additional resource records")
print("qd     - Query domain (contains qname, qtype, qclass)")
print("an     - Answer records (present in responses)")
print("_____________DNS QTypes (Common Types)______________\n")
print("Type 1  - A (IPv4 address)")
print("Type 2  - NS (Name Server)")
print("Type 5  - CNAME (Canonical Name / Alias)")
print("Type 15 - MX (Mail Exchange)")
print("Type 28 - AAAA (IPv6 address)")

print("\n_____________DNS Options______________\n")
print(inspect.signature(DNS))

print("\n_____________How to make first DNS Query______________\n")
packet = IP(dst="8.8.8.8")/UDP(dport=53, sport=12345)/DNS(id=1, qr=0, opcode=0, rd=1, qd=DNSQR(qname="google.com", qtype=1))
print("____show of the packet____")
print(packet.show())

print("\n____summary of the packet____")
print(packet.summary())

print("\n======DHCP (Dynamic Host Configuration Protocol)======\n")
print("DHCP components\n______________\n")
print(ls(DHCP))

print("\n_____________DHCP Fields Explanation (Important)______________\n")
print("Note: The BOOTP fields (op, htype, hlen, xid, etc.) are inherited from the BOOTP layer.")
print("op     - Operation (1 = Request/Discover, 2 = Reply/Offer/Ack)")
print("htype  - Hardware type (1 = Ethernet)")
print("hlen   - Hardware length (6 for MAC address)")
print("xid    - Transaction ID (unique per session)")
print("secs   - Seconds elapsed since client started")
print("flags  - Flags (e.g., Broadcast flag)")
print("ciaddr - Client IP address (if known)")
print("yiaddr - Offered or Assigned IP address (Your IP)")
print("siaddr - DHCP Server IP address")
print("giaddr - Gateway/Relay Agent IP address")
print("chaddr - Client hardware address (MAC)")
print("sname  - DHCP Server hostname")
print("file   - Boot file name")
print("options - DHCP options (crucial, contains message-type and parameters)")
print("_____________DHCP Common Options (message-type)______________\n")
print("Option 53 - DHCP Message Type")
print("  value 1 - DHCPDISCOVER")
print("  value 2 - DHCPOFFER")
print("  value 3 - DHCPREQUEST")
print("  value 5 - DHCPACK")
print("  value 6 - DHCPNAK")
print("  value 7 - DHCPRELEASE")
print("Other common options: subnet_mask (1), router (3), dns_server (6),")
print("hostname (12), domain_name (15), requested_addr (50), lease_time (51), dhcp_server (54).")

print("\n_____________DHCP Options______________\n")
print(inspect.signature(DHCP))

print("\n_____________How to make first DHCP Discover______________\n")
# Correct construction: BOOTP for fixed fields, DHCP for options
packet = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")/IP(dst="255.255.255.255", src="0.0.0.0")/UDP(dport=67, sport=68)/BOOTP(op=1, xid=0x12345678, chaddr="00:11:22:33:44:55")/DHCP(options=[("message-type", "discover"), ("hostname", "client-pc"), "end"])
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
