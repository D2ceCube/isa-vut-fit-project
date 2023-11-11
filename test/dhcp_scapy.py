from scapy.all import *

yiaddr_addr = "192.168.0."

x = 0
while x < 6:
    yiaddr_addr = "192.168.0." + str(x)
    dhcp_ack_1 = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
        BOOTP(op=2, xid=0x01020304, yiaddr=yiaddr_addr) / DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"), "end"])
    sendp(dhcp_ack_1, iface="eth0")
    x += 1
