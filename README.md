# Above

Invisible protocol sniffer for finding vulnerabilities in the network. Designed for pentesters and security engineers.

![](/banner/banner.png)

```
Above: Invisible network protocol sniffer
Designed for pentesters and security engineers

Author: Magama Bazarov, <caster@exploit.org>
Pseudonym: Caster
Version: 2.6
Codename: Introvert
```

# Disclaimer

**All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool**.

**It is a specialized network security tool that helps both pentesters and security professionals**.

---

# Mechanics

Above is a invisible network sniffer for finding vulnerabilities in network equipment. It is based entirely on network traffic analysis, so it does not make any noise on the air. He's invisible. Completely based on the Scapy library.

> Above allows pentesters to automate the process of finding vulnerabilities in network hardware. Discovery protocols, dynamic routing, 802.1Q, ICS Protocols, FHRP, STP, LLMNR/NBT-NS, etc.

## Supported protocols

Detects up to 27 protocols:

```
MACSec (802.1X AE)
EAPOL (Checking 802.1X versions)
ARP (Passive ARP, Host Discovery)
CDP (Cisco Discovery Protocol)
DTP (Dynamic Trunking Protocol)
LLDP (Link Layer Discovery Protocol) 
802.1Q Tags (VLAN)
S7COMM (Siemens)
OMRON
TACACS+ (Terminal Access Controller Access Control System Plus)
ModbusTCP
STP (Spanning Tree Protocol)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
BGP (Border Gateway Protocol)
VRRP (Virtual Router Redundancy Protocol)
HSRP (Host Standby Redundancy Protocol)
GLBP (Gateway Load Balancing Protocol)
IGMP (Internet Group Management Protocol)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCP (Dynamic Host Configuration Protocol)
DHCPv6 (Dynamic Host Configuration Protocol v6)
ICMPv6 (Internet Control Message Protocol v6)
SSDP (Simple Service Discovery Protocol)
MNDP (MikroTik Neighbor Discovery Protocol)
```
## Operating Mechanism

Above works in two modes:

- Hot mode: Sniffing on your interface specifying a timer
- Cold mode: Analyzing traffic dumps

The tool is very simple in its operation and is driven by arguments:

- Interface: Specifying the network interface on which sniffing will be performed
- Timer: Time during which traffic analysis will be performed
- Input: The tool takes an already prepared `.pcap` as input and looks for protocols in it
- Output: Above will record the listened traffic to `.pcap` file, its name you specify yourself
- Passive ARP: Detecting hosts in a segment using Passive ARP

```
usage: above.py [-h] [--interface INTERFACE] [--timer TIMER] [--output OUTPUT] [--input INPUT] [--passive-arp]

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Interface for traffic listening
  --timer TIMER         Time in seconds to capture packets, if not set capture runs indefinitely
  --output OUTPUT       File name where the traffic will be recorded
  --input INPUT         File name of the traffic dump
  --passive-arp         Passive ARP (Host Discovery)
```

---

## Information about protocols

The information obtained will be useful not only to the pentester, but also to the security engineer, he will know what he needs to pay attention to.

When Above detects a protocol, it outputs the necessary information to indicate the attack vector or security issue:

- Impact: What kind of attack can be performed on this protocol;

- Tools: What tool can be used to launch an attack;

- Technical information: Required information for the pentester, sender MAC/IP addresses, FHRP group IDs, OSPF/EIGRP domains, etc.

- Mitigation: Recommendations for fixing the security problems

- Source/Destination Addresses: For protocols, Above displays information about the source and destination MAC addresses and IP addresses

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
caster@kali:~$ git clone https://github.com/casterbyte/Above
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
git clone https://github.com/casterbyte/Above
cd Above/
sudo python3 setup.py install
```

Don't forget to **deactivate** your firewall on macOS!
#### Settings > Network > Firewall
--------------------------

# How to Use

## Hot mode

> Above requires root access for sniffing

Above can be run with or without a timer:

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120
```
> To stop traffic sniffing, press CTRL + С
>
> WARNING! Above is not designed to work with tunnel interfaces (L3) due to the use of filters for L2 protocols. Tool on tunneled L3 interfaces may not work properly.

Example:

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120

-----------------------------------------------------------------------------------------
[+] Start sniffing...

[*] After the protocol is detected - all necessary information about it will be displayed
--------------------------------------------------
[+] Detected SSDP Packet
[*] Attack Impact: Potential for UPnP Device Exploitation
[*] Tools: evil-ssdp
[*] SSDP Source IP: 192.168.0.251
[*] SSDP Source MAC: 02:10:de:64:f2:34
[*] Mitigation: Ensure UPnP is disabled on all devices unless absolutely necessary, monitor UPnP traffic
--------------------------------------------------
[+] Detected MDNS Packet
[*] Attack Impact: MDNS Spoofing, Credentials Interception
[*] Tools: Responder
[*] MDNS Spoofing works specifically against Windows machines
[*] You cannot get NetNTLMv2-SSP from Apple devices
[*] MDNS Speaker IP: fe80::183f:301c:27bd:543
[*] MDNS Speaker MAC: 02:10:de:64:f2:34
[*] Mitigation: Filter MDNS traffic. Be careful with MDNS filtering
--------------------------------------------------
```

If you need to record the sniffed traffic, use the `--output` argument

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120 --output above.pcap
```
> If you interrupt the tool with CTRL+C, the traffic is still written to the file

## Cold mode

If you already have some recorded traffic, you can use the `--input` argument to look for potential security issues

```bash
caster@kali:~$ above --input ospf-md5.cap
```

Example:

```bash
caster@kali:~$ sudo above --input ospf-md5.cap

[+] Analyzing pcap file...

--------------------------------------------------
[+] Detected OSPF Packet
[+] Attack Impact: Subnets Discovery, Blackhole, Evil Twin
[*] Tools: Loki, Scapy, FRRouting
[*] OSPF Area ID: 0.0.0.0
[*] OSPF Neighbor IP: 10.0.0.1
[*] OSPF Neighbor MAC: 00:0c:29:dd:4c:54
[!] Authentication: MD5
[*] Tools for bruteforce: Ettercap, John the Ripper
[*] OSPF Key ID: 1
[*] Mitigation: Enable passive interfaces, use authentication
--------------------------------------------------
[+] Detected OSPF Packet
[+] Attack Impact: Subnets Discovery, Blackhole, Evil Twin
[*] Tools: Loki, Scapy, FRRouting
[*] OSPF Area ID: 0.0.0.0
[*] OSPF Neighbor IP: 192.168.0.2
[*] OSPF Neighbor MAC: 00:0c:29:43:7b:fb
[!] Authentication: MD5
[*] Tools for bruteforce: Ettercap, John the Ripper
[*] OSPF Key ID: 1
[*] Mitigation: Enable passive interfaces, use authentication
```



# Passive ARP

The tool can detect hosts without noise in the air by processing ARP frames in passive mode

```bash
caster@kali:~$ sudo above --interface eth0 --passive-arp --timer 10

[+] Host discovery using Passive ARP

--------------------------------------------------
[+] Detected ARP Reply
[*] ARP Reply for IP: 192.168.1.88
[*] MAC Address: 00:00:0c:07:ac:c8
--------------------------------------------------
[+] Detected ARP Reply
[*] ARP Reply for IP: 192.168.1.40
[*] MAC Address: 00:0c:29:c5:82:81
--------------------------------------------------
```

# Outro

I wrote this tool because of the track "A View From Above (Remix)" by KOAN Sound.
This track was everything to me when I was working on this sniffer.

---

