# Above (Kali Linux)

Invisible protocol sniffer for finding vulnerabilities in the network. Designed for pentesters and security engineers.

Author: Magama Bazarov

![](/cover/kali-above.svg)

# Disclaimer

**All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool**.

**It is a specialized network security tool that helps both pentesters and security professionals**.

---

# Mechanics

Above is a invisible network sniffer for finding vulnerabilities in network equipment. It is based entirely on network traffic analysis, so it does not make any noise on the air. He's invisible. Completely based on the Scapy library.

> Above allows pentesters to automate the process of finding vulnerabilities in network hardware. Discovery protocols, dynamic routing, FHRP, STP, LLMNR/NBT-NS, etc.

## Supported protocols

Detects up to 14 protocols:

```
CDP (Cisco Discovery Protocol)
DTP (Dynamic Trunking Protocol)
802.1Q Tags (VLAN)
LLDP (Link Layer Discovery Protocol) 
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
VRRPv2/v3 (Virtual Router Redundancy Protocol)
HSRPv1 (Host Standby Redundancy Protocol)
STP (Spanning Tree Protocol)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCPv6 (Dynamic Host Configuration Protocol v6)
SSDP (Simple Service Discovery Protocol)
MNDP (MikroTik Neighbor Discovery Protocol)
```
> All protocols are analyzed simultaneously due to the threads design

## Operating Mechanism

Above works in two modes:

- Hot mode: Sniffing on your interface specifying a timer
- Cold mode: Analyzing traffic dumps

The tool is very simple in its operation and is driven by arguments:

- Interface: Specifying the network interface on which sniffing will be performed
- Timer: Time during which traffic analysis will be performed
- Output pcap: Above will record the listened traffic to pcap file, its name you specify yourself
- Input pcap: The tool takes an already prepared .pcap as input and looks for protocols in it

```
usage: above [-h] [--interface INTERFACE] [--timer TIMER] [--output-pcap OUTPUT_FILE] [--input-pcap INPUT_FILE]

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Specify the interface
  --timer TIMER         Specify the timer value (seconds)
  --output-pcap OUTPUT_FILE
                        Specify the output pcap file to record traffic
  --input-pcap INPUT_FILE
                        Specify the input pcap file to analyze traffic
```



## Traffic Sniffing Demo (Hot mode)

![](/demos/hotmode.gif)

---

## Information about protocols

The information obtained will be useful not only to the attacker, but also to the security engineer, he will know what he needs to pay attention to.

When Above detects a protocol, it outputs the necessary information to indicate the attack vector or security issue:

- Impact: What kind of attack can be performed on this protocol;

- Tools: What tool can be used to launch an attack;

- Technical information: Required information for the attacker, sender IP addresses, FHRP group IDs, OSPF/EIGRP domains, etc.

- Mitigation: Recommendations for fixing the security problems

---

# Installation

### Linux
You can install Above directly from the Kali Linux repositories
```bash
caster@kali:~$ sudo apt update && sudo apt install above
```

Or...

```bash
caster@kali:~$ sudo apt-get install python3-scapy python3-colorama python3-setuptools
caster@kali:~$ git clone https://github.com/cursedpkt/Above
caster@kali:~$ cd Above/
caster@kali:~/Above$ sudo python3 setup.py install
```

### macOS:
```bash
# Install python3 first
brew install python3
# Then install required dependencies
sudo pip3 install scapy colorama setuptools

# Clone the repo
git clone https://github.com/cursedpkt/Above
cd Above/
sudo python3 setup.py install
```

Don't forget to **deactivate** your firewall on macOS!
#### Settings > Network > Firewall.

### Windows:
```
P:\>git clone https://github.com/cursedpkt/above
P:\>cd above/
P:\above>pip3 install scapy
P:\above>pip3 install colorama
P:\above>python above.py --help
```

> The development of this version of Above was based on Python version **3.11.6**, Scapy version **2.5.0.dev212**

# Windows Compatibility

Above can also work on Windows, provided the winpcap driver is installed, without which sniffing with Scapy is impossible.

You can use [auto-py-to-exe](https://pypi.org/project/auto-py-to-exe/) to compile the .py script

# How to Use

First, it's worth switching the interface to promiscuous mode

> Above requires root access for sniffing

### Linux
```bash
caster@kali:~$ sudo ip link set eth0 promisc on 
```

### macOS
For Wi-Fi:
Remember to replace `en1` with your target interface.
```bash
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en1 sniff
```

For other:
There is no need to enable promiscuous mode manually for ethernet interfaces, it is done automatically.

Above requires at least an interface and a timer at startup. Choose the timer from your calculations.

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120
```
> To stop traffic sniffing, press CTRL + С

If you need to record the sniffed traffic, use the `--output-pcap` argument

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120 --output-pcap dump.pcap
```
> By specifying only the --interface and --output-pcap - Above will also be able to start, without a timer

If you already have some recorded traffic, you can use the `--input-pcap` argument to look for potential security issues

```bash
caster@kali:~$ above --input-pcap dump.pcap
```

> WARNING! Above is not designed to work with tunnel interfaces (L3) due to the use of filters for L2 protocols. Tool on tunneled L3 interfaces may not work properly.

## Pcap Analyzing Demo (Cold mode)

![](/demos/cold-mode.gif)


# Outro

I wrote this tool because of the track "A View From Above (Remix)" by KOAN Sound.
This track was everything to me when I was working on this sniffer.

---

