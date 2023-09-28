from scapy.all import *

# Create a DHCP Discover packet
dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
    BOOTP(op=1, xid=0x01020304) / DHCP(options=[("message-type", "discover"), "end"])

# Create a DHCP Offer packet
dhcp_offer = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
    BOOTP(op=2, xid=0x01020304, yiaddr="172.133.175.45") / DHCP(options=[("message-type", "offer"), ("subnet_mask", "255.255.240.0"), "end"])




# Create a DHCP Ack packet
# Change the yiaddr to what you want you need
dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
    BOOTP(op=2, xid=0x01020304, yiaddr="192.168.0.12") / DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"), "end"])


sendp(dhcp_ack, iface="eth0")
sendp(dhcp_ack, iface="eth0")