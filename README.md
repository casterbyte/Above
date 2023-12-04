# Above v2.2 (Codename: Vettel)

Invisible protocol sniffer for finding vulnerabilities in the network. Designed for pentesters and security professionals.

Designed for pentesters and security professionals

![](/cover/tool_cover.png)
> Cover for tool

---

# Disclaimer

**All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool**.

**It is a specialized network security tool that helps both pentesters and security professionals**.

---

# Mechanics

Above is a invisible network sniffer for finding vulnerabilities in network equipment. It is based entirely on network traffic analysis, so it does not make any noise on the air. He's invisible. Completely based on the Scapy library.

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

> All protocols are analyzed simultaneously due to the threads design

## Operating Mechanism

Above works in two modes:

- Hot sniffing on your interface specifying a timer
- Analyzing traffic dumps in cold mode (Offline)

The tool is very simple in its operation and is driven by arguments:

- Interface. Specifying the network interface on which sniffing will be performed
- Timer. Time during which traffic analysis will be performed
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



## Traffic Sniffing Demo

![](/demos/sniffing-demo.gif)
> Sorry for not the best quality, Github has file size limits on uploads

---

## Information about protocols

The information obtained will be useful not only to the attacker, but also to the security engineer, he will know what he needs to pay attention to.

When Above detects a protocol, it outputs the necessary information to indicate the attack vector or security issue:

- **Impact** - What kind of attack can be performed on this protocol;

- **Tools** - What tool can be used to launch an attack;

- **Technical information** - Required information for the attacker, sender IP addresses, FHRP group IDs, OSPF/EIGRP domains, etc.

  > This information can also be used by a security engineer to improve network security

---

# Installation

Above is very easy to install using **setup.py**

```bash
caster@kali:~$ git clone https://github.com/wearecaster/Above
caster@kali:~$ cd Above/
caster@kali:~/Above$ sudo python3 setup.py install 
```

> The development of this version of Above was based on Python version **3.11.6**, Scapy version **2.5.0.dev212**

# Windows Compatibility

Above can also work on Windows, provided the winpcap driver is installed, without which sniffing with Scapy is impossible.

You can use [auto-py-to-exe](https://pypi.org/project/auto-py-to-exe/) to compile the .py script

# How to Use

First, it's worth switching the interface to promiscuous mode

> Above requires root access for sniffing

```bash
caster@kali:~$ sudo ip link set eth0 promisc on 
```

Above requires at least an interface and a timer at startup. Choose the timer from your calculations.

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120
```
If you need to record the sniffed traffic, use the `--output-pcap` argument

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120 --output-pcap dump.pcap
```

If you already have some recorded traffic, you can use the `--input-pcap` argument to look for potential security issues

```
caster@kali:~$ above --input-pcap dump.pcap
```

## PCAP Analyzing Demo

![](/demos/pcap-analyzing.gif)
> Sorry for not the best quality, Github has file size limits on uploads

# Suggestions

If you find bugs in this tool or have suggestions on how to improve this tool, feel free to email me personally!

# Outro

This tool is dedicated to the track "A View From Above (Remix)" performed by KOAN Sound.
This track was all the inspiration for me during the process of working on this tool.

---

