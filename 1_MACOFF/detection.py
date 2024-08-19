from scapy.all import sniff
from scapy.layers.l2 import Ether

THRESHOLD = 0

# Initialize a set to store unique MAC addresses
unique_mac_addresses = set()

def packet_callback(packet):
    if packet.haslayer(Ether):
        # Add the source MAC address to the set
        unique_mac_addresses.add(packet[Ether].src)

def monitor_traffic(interface, duration=60):
    print(f"Monitoring traffic on {interface} for {duration} seconds...")
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    print("Capture complete.")

    # Check if the number of unique MAC addresses exceeds the threshold
    unique_mac_count = len(unique_mac_addresses)
    print(f"Number of unique MAC addresses: {unique_mac_count}")

    if unique_mac_count > THRESHOLD:
        print("MAC flood detected! Your attack might have succeeded.")
    else:
        print("No MAC flood detected. Your attack might have failed.")

if __name__ == "__main__":
    THRESHOLD = int(input("Now will test for MAC TAble overflow attacks. Please enter a threshold: "))
    interface = "eth0"  # Replace with your network interface
    monitor_traffic(interface)

