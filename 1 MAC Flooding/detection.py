from scapy.all import sniff
from scapy.layers.l2 import Ether

initial_mac_addresses = set()
final_mac_addresses = set()

def packet_callback(packet, mac_set):
    if packet.haslayer(Ether):
        # Add the source MAC address to the provided set
        mac_set.add(packet[Ether].src)

def capture_mac_addresses(interface, duration, mac_set):
    print(f"Capturing MAC addresses on {interface} for {duration} seconds...")
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, mac_set), timeout=duration)
    print("Capture complete.")

def monitor_for_macof_attack(interface, threshold=200, initial_duration=10, detection_duration=30):
    # Step 1: Capture the MAC adresses for 10 seconds.
    print("Initial MAC address collection phase...")
    capture_mac_addresses(interface, initial_duration, initial_mac_addresses)
    initial_mac_count = len(initial_mac_addresses)
    print(f"Initial number of unique MAC addresses: {initial_mac_count}")

    # Step 2: Wait for user to run macof and then listen for 30 seconds
    print("\nListening for possible MAC table overflow attack...")
    capture_mac_addresses(interface, detection_duration, final_mac_addresses)
    final_mac_count = len(final_mac_addresses)
    print(f"Number of unique MAC addresses after running macof: {final_mac_count}")

    # Step 3: Calculate the difference
    mac_difference = final_mac_count - initial_mac_count
    print(f"Difference in unique MAC addresses: {mac_difference}")

    # Step 4: Check if the difference exceeds the threshold
    if mac_difference > threshold:
        print("MAC flood detected! The network is likely vulnerable to MAC table overflow attacks.")
    else:
        print("No significant MAC flood detected. The network may not be vulnerable.")

if __name__ == "__main__":
    interface = input("Enter your interface: ")
    monitor_for_macof_attack(interface)

