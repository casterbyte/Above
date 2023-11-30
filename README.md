# Above

Network protocol sniffer, allows you to find network attack vectors. 
Designed for pentesters and network security engineers.

![](/logo/above_logo.png)

---

# Disclaimer

**All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool**

---

# Mechanics

Above is a standalone network protocol sniffer. It is based entirely on network traffic analysis, so it does not make any noise on the air. He's invisible. Completely based on the Scapy library.

Auxiliary libraries are also used:

- threading - to work with threads
- shutil - to work with text in a banner
- argparse - to control arguments
- signal - to interrupt the code correctly
- sys - is used together with signal to handle an interrupt

> The main task that Above solves is to search for L2/L3 protocols inside the network and to find vulnerabilities in configurations based on sniffed traffic.

## Supported protocols

Detects up to 12 protocols:

```
CDP (Cisco Discovery Protocol)
DTP (Dynamic Trunking Protocol) 
Dot1Q (VLAN Tagging)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
VRRPv2 (Virtual Router Redundancy Protocol)
HSRPv1 (Host Standby Redundancy Protocol)
STP (Spanning Tree Protocol)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCPv6 (Dynamic Host Configuration Protocol v6)
```

> I would like to note that sniffing of all protocols is done simultaneously to reduce the time spent on traffic analysis. I achieved this by using special threads.

## Launching

The startup is done along with **two arguments**. Thanks to arguments, the user defines the interface of his system and specifies the timer within which sniffing will be performed. The timer is specified in seconds. The specified timer applies to all protocols.

> **LIMITATIONS:** Root permissions are required to run the utility

```bash
caster@kali:~/Above$ sudo python3 Above.py --interface eth0 --timer 100
```

> **TIMER VALUE:** The recommended timer value is up to 120-150 seconds, usually enough to detect protocols on the air. You can increase the timer time if needed. Depending on the network infrastructure

## Demo

![](/demo/above_demo.gif)

---

## Information about protocols

If a particular protocol is on the air, Above displays the following information:

- **Impact** - Shows what the impact of a network attack will be

- **Tools** - Indicates the necessary utilities to perform the attack 

- **Technical information** - Indicates the MAC and IP addresses of packet senders, OSPF zone IDs, 802.1Q tags, FHRP priority values, authentication availability, and other protocol service information, etc. 

This information will be useful to the pentester, to create a network attack vector, but also to the security engineer who can protect network equipment.

---

# Installation

Above depends on several Python libraries. You should install them from setup.py

```bash
caster@kali:~/Above$ sudo python3 setup.py install 
```

> The development of this version of Above was based on Python version **3.11.6**, Scapy version **2.5.0.dev212**

# Windows Compatibility

Above can also work on Windows, provided the winpcap driver is installed, without which sniffing with Scapy is impossible.

You can use [auto-py-to-exe](https://pypi.org/project/auto-py-to-exe/) to compile the .py script

# How to Use

First, it's worth switching the interface to promiscuous mode

```
caster@kali:~/Above$ sudo ip link set eth0 promisc on 
```

Like I said earlier, Above just needs two arguments to run. After that it will start listening to traffic on your interface, searching for protocols and displaying information about them. The tool is very easy to use

```bash
caster@kali:~/Above$ sudo python3 Above.py --interface eth0 --timer 120
```
![](/screens/above_example.png)

> If necessary, you can interrupt the tool by pressing CTRL + C

# Possible Suggestions

If you have any suggestions for improving the scanner or adding new features, feel free to email me personally.

# Metadata

```
Caster - Above

Written by: Magama Bazarov
Alias: Caster
Genre: Offensive, Defensive
Label: github.com
Version: 2.1
Codename: Vivid
```

# Outro

This tool is dedicated to the track "A View From Above (Remix)" performed by KOAN Sound.
This track was all the inspiration for me during the process of working on this tool.

---

