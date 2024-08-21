# Low-Layer Strike Tool

Welcome to the Low-Layer Strike Tool repository. This tool is being developed to simulate various network attacks on a given topology, as seen in the initial setup, and to aid in learning about network security vulnerabilities at the data link and network layers. The project will evolve over time, with each phase introducing new features and attack vectors.

## Initial Topology

Can be seen from TOPOLOGY.png
*This is the initial topology used for testing and development.*

## Overview

The Low-Layer Strike Tool is designed to automate a range of network attacks targeting Layer 2 and Layer 3 protocols. The tool is primarily written in Python using the `scapy` library for packet crafting and will include C++ for performance-critical tasks.

### Attack Vectors Implemented

In the initial phase, the tool will support the following network attacks:

- **CAM Table Flooding Attack**: Overflows the CAM table of a switch by sending a flood of Ethernet frames with random MAC addresses.
- **CDP Flooding Attack**: Exploits the Cisco Discovery Protocol by sending crafted CDP packets to the network to gain information or cause disruptions.
- **DHCP Spoofing**: Responds to DHCP requests with fake DHCP responses to perform man-in-the-middle attacks.
- **DHCP Starvation (Rogue DHCP Server)**: Exhausts the DHCP server’s IP address pool by sending numerous DHCP requests.
- **ARP Protocol Attacks**: Performs ARP poisoning by sending false ARP messages to associate the attacker’s MAC address with another host’s IP address.
- **Switch Spoofing**: Tricks a switch into believing the attacking device is a legitimate switch in order to capture traffic from multiple VLANs.
- **VTP Attacks**: Exploits the VLAN Trunking Protocol to create, modify, or delete VLANs in a network.
- **STP Attacks**: Manipulates the Spanning Tree Protocol to force the network to choose a compromised switch as the root bridge.
- **VLAN Attacks**: Focuses on VLAN hopping and VLAN double tagging to access restricted VLANs.
- **HSRP Attacks**: Exploits the Hot Standby Router Protocol to cause a denial of service or man-in-the-middle attack by taking over the active router role.
- **IP Spoofing Attacks**: Sends packets with forged source IP addresses to impersonate another device.
- **Telnet Attacks**: Targets Telnet sessions for session hijacking or credential sniffing.
- **SNMP Protocol Attacks**: Attempts to exploit vulnerabilities in the Simple Network Management Protocol for information disclosure or remote control of devices.

## Getting Started

1. **Prerequisites**:
   - Python 3.x
   - `scapy` library (`pip install scapy`)
   - A C++ compiler (for later phases)
   
2. **Installation**:
   - Clone this repository:  
     ```bash
     git clone https://github.com/yourusername/low-layer-strike-tool.git
     cd low-layer-strike-tool
     ```

3. **Usage**:
   - The attacks can be executed by running the respective Python scripts in the `attacks/` directory. Each attack will have its own script with specific usage instructions.

4. **Contributing**:
   - Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.


---

*Note: The tool is intended for educational and ethical testing purposes only. Unauthorized use of this tool against networks or devices that you do not own or have explicit permission to test is illegal and unethical.*

