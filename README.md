# Above

**Network Vulnerability Scanner by Caster**

**Direction: Penetration Testing**  
**Genre: Offensive**  
**Release Date: 1 May 2023**  
**Label: Github**

![](cover.png)


## Mechanics

This script is based on a sniff of network traffic. "Above" is fully autonomous and works in passive mode, creating no noise on the air. Since the 2.0 release, it supports 18 protocols

```
MACSec (802.1AE)
MNDP (Mikrotik Neighbor Discovery Protocol)
DTP (Dynamic Trunking Protocol)
CDP (Cisco Discovery Protocol)
EDP (Extreme Discovery Protocol)
ESRP (Extreme Standby Router Protocol)
LLDP (Link Layer Discovery Protocol)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
VRRP (Virtual Router Redundancy Protocol)
HSRP (Host Standby Redundancy Protocol)
GLBP (Gateway Load Balancing Protocol)
STP (Spanning Tree Protocol)
PVST (Per VLAN Spanning Tree)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCPv6 (Dynamic Host Configuration Protocol v6)
```

The scanner waits for the following arguments as input:

  - Network interface
  - Timeout: The amount of time that a packet will be waiting for, according to the filters inside the scanner
  - Protocol
  - Promisc Mode
  - Resolve MAC: Vendor detection by MAC (requires Internet access, creates a little noise in the form of HTTP requests

Example (OSPF and VRRP protocol scan):

```
sudo python3 Above.py --interface eth0 --timeout 60 --ospf --vrrp --resolve-mac --promisc-mode
```

When the tool finishes analyzing the protocol, it outputs a little information about its configuration, the impact from the attack, which tool the attacker uses

## Install

Above" requires some dependencies to be installed. If necessary, you can use virtualenv

```
sudo pip3 install -r requirements.txt
```

## Code Design Issues

"Above" has problems with the code in terms of design/refactoring. I was putting the emphasis specifically on the workability of the code.

## Last Word

This tool is dedicated to the track "View From Above (Remix)" by KOAN Sound
