from scapy.all import *

# Create a DHCP Discover packet (Client requesting an IP address)
dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
    BOOTP(op=1, xid=0x01020304) / DHCP(options=[("message-type", "discover"), "end"])

# Create a DHCP Offer packet (Server offering an IP address)
dhcp_offer = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
    BOOTP(op=2, xid=0x01020304, yiaddr="172.133.175.45") / DHCP(options=[("message-type", "offer"), ("subnet_mask", "255.255.240.0"), "end"])


dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
    BOOTP(op=2, xid=0x01020304, yiaddr="172.133.175.45") / DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.240.0"), "end"])

# Print and send the packets
#print("DHCP Discover packet:")
#dhcp_discover.show()
sendp(dhcp_discover, iface="eth0")

#print("\nDHCP Offer packet:")
#dhcp_offer.show()
sendp(dhcp_offer, iface="eth0")
sendp(dhcp_ack, iface="eth0")
