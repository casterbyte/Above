#!/usr/bin/env python3

import argparse
from scapy.all import sniff, rdpcap, wrpcap, Ether, Dot1Q, IP, HSRP, HSRPmd5, VRRP, VRRPv3, STP, IPv6, AH, Dot3, ARP, UDP
from scapy.contrib.macsec import MACsec, MACsecSCI
from scapy.contrib.eigrp import EIGRP, EIGRPAuthData
from scapy.contrib.ospf import OSPF_Hdr
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4
from scapy.contrib.dtp import DTP
from scapy.layers.eap import EAPOL
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import *
from scapy.layers.inet6 import ICMPv6ND_RS
from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUSystemDescription
from colorama import Fore, Style, init
import shutil


init(autoreset=True)


# This section is code for displaying the logo and author information
text = r"""
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@                                         @@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@                                     @@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""

for line in text.split("\n"):
    terminal_width = shutil.get_terminal_size().columns
    padding = " " * ((terminal_width - len(line)) // 2)
    print(padding + line)


def centered_text(text):
    terminal_width = shutil.get_terminal_size().columns
    padding = " " * ((terminal_width - len(text)) // 2)
    return f"{padding}{text}"

print(centered_text("Invisible network protocol sniffer"))
print(centered_text("Designed for pentesters and security engineers"))
print(centered_text(Fore.YELLOW + "Version 2.5, Codename: Ayrton Senna"))
print(centered_text(Fore.YELLOW + "Author: Magama Bazarov, <caster@exploit.org>"))

# Frame for output
def print_frame(title, content):
    if not content:
        return
    max_width = max(len(line) for line in content)
    title_length = len(title) + 2
    width = max(max_width, title_length) + 4

    print(Fore.WHITE + Style.BRIGHT + '┌' + '─' * (width - 2) + '┐')
    print(Fore.WHITE + Style.BRIGHT + f'│ {(title):^{width-4}} │')
    print(Fore.WHITE + Style.BRIGHT + '├' + '─' * (width - 2) + '┤')
    for line in content:
        print(Fore.WHITE + Style.BRIGHT + f'│ {line:<{width-4}} │')
    print(Fore.WHITE + Style.BRIGHT + '└' + '─' * (width - 2) + '┘')

# Decode ospf plaintext password
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    return bytes.fromhex(hex).decode('utf-8')

# .pcap parsing, cold mode
def analyze_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    for packet in packets:
        packet_detection(packet)

# Above core
def packet_detection(packet):
    # for capture protocols to pcap
    if packet.haslayer(OSPF_Hdr) or packet.haslayer(CDPv2_HDR) or packet.haslayer(MACsec) or packet.haslayer(EAPOL) \
        or packet.haslayer(EIGRP) or packet.haslayer(DTP) or packet.haslayer(STP) or packet.haslayer(LLDPDU) \
        or packet.haslayer(HSRP) or packet.haslayer(VRRP) or packet.haslayer(VRRPv3) \
        or packet.haslayer(BOOTP) or packet.haslayer(DHCP) or packet.haslayer(IGMP) or packet.haslayer(ICMPv6ND_RS) \
        or packet.haslayer(ARP) or packet.haslayer(IPv6) or packet.haslayer(Dot1Q) or packet.haslayer(UDP) \
        and packet[UDP].dport in [137, 5353, 5355, 3222, 546, 547, 1900]:
        packets.append(packet)

    # MACSec
    if packet.haslayer(MACsec):
        title = "Detected MACSec"
        content = [
            "[!] The network may be using 802.1X, keep that in mind",
            f"[*] System Identifier: {packet[MACsec][MACsecSCI].system_identifier if packet[MACsec][MACsecSCI].system_identifier else 'Not Found'}",
        ]
        print_frame(title, content)
    
    # OSPF
    if packet.haslayer(OSPF_Hdr):
        title = "Detected OSPF Packet"
        content = [
            "[*] Attack Impact: Subnets Discovery, Blackhole, Evil Twin",
            "[*] Tools: Loki, Scapy, FRRouting",
            f"[*] OSPF Area ID: {packet[OSPF_Hdr].area}",
            f"[*] OSPF Neighbor IP: {packet[OSPF_Hdr].src}",
            f"[*] OSPF Neighbor MAC: {packet[Ether].src}",
        ]
        # No Auth
        if packet[OSPF_Hdr].authtype == 0x0:
            content.append("[*] Authentication: No")
        # Plaintext Auth
        elif packet[OSPF_Hdr].authtype == 0x1:
            raw = packet[OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            content.append(f"[*] Authentication: Plaintext Phrase: {string}")
        # Crypt Auth (MD5)
        elif packet[OSPF_Hdr].authtype == 0x02:
            content.append("[*] Authentication: MD5")
            content.append(f"[*] Tools for bruteforce: Ettercap, John the Ripper")
            content.append(f"[*] OSPF Key ID: {packet[OSPF_Hdr].keyid}")

        content.append("[*] Mitigation: Enable passive interfaces, use cryptographic authentication")
        print_frame(title, content)

    # HSRP
    if packet.haslayer(HSRP) and packet[HSRP].state == 16: 
        title = "Detected HSRP Packet"
        content = [
            "[*] Attack Impact: MITM",
            "[*] Tools: Scapy, Loki",
            "[*] HSRP State: Active",
            f"[*] HSRP Group: {packet[HSRP].group}",
            f"[*] HSRP Priority: {packet[HSRP].priority}",
            f"[*] HSRP Virtual IP: {packet[HSRP].virtualIP}",
        ]
        if packet.haslayer(HSRPmd5):
            content.append("[*] Authentication: MD5")
            content.append("[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
        else:
            if packet[HSRP].auth != b'\x00' * 8:
                hsrpv1_plaintext = packet[HSRP].auth.decode('utf-8').rstrip('\x00')
                content.append(f"[*] Authentication: Plaintext: {hsrpv1_plaintext}")

        content.append("[*] Mitigation: Use priority 255, use cryptographic authentication, filtering HSRP traffic with ACL")
        print_frame(title, content)

    # VRRPv2
    if packet.haslayer(IP) and packet[IP].dst == "224.0.0.18":
        content = []
        title = "Detected VRRP Packet"
        if packet.haslayer(VRRP):
            vrrp_layer = packet.getlayer(VRRP)
            src_mac = packet[Ether].src
            src_ip = packet[IP].src
            content = [
                f"[*] Router Priority: {vrrp_layer.priority}",
                f"[*] VRRP Speaker IP: {src_ip}",
                f"[*] VRRP Speaker MAC: {src_mac}",
                f"[*] VRRP Version: {vrrp_layer.version}",
                f"[*] VRRP Group Number: {vrrp_layer.vrid}",
                "[*] Mitigation: Filter VRRP traffic using ACL"
            ]
            if vrrp_layer.authtype == 1:
                content.append("[*] Authentication: Simple Authentication")
            else:
                content.append("[*] Authentication: No")
        if packet.haslayer(AH):
            content.append("[!] Authentication: AH Header detected, packet is authenticated")

        print_frame(title, content)

    # VRRPv3
    if packet.haslayer(VRRPv3):
        title = "Detected VRRPv3 Packet"
        content = [
            f"[*] Router Priority: {packet[VRRPv3].priority if packet[VRRPv3].priority <= 255 else 'Not Found'}",
            "[*] Attack Impact: MITM",
            "[*] Tools: Scapy, Loki",
            f"[*] VRRPv3 Group Number: {packet[VRRPv3].vrid}",
            f"[*] VRRPv3 Speaker IP: {packet[IP].src}",
            f"[*] VRRPv3 Speaker MAC: {packet[Ether].src}",
            f"[*] VRRPv3 Virtual IP Address: {', '.join(packet[VRRPv3].addrlist)}",
        ]

        content.append("[*] Mitigation: Filter VRRP traffic using ACL")
        print_frame(title, content)

    # GLBP
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 3222:
            title = "Detected GLBP Packet"
            content = [
                "[*] Attack Impact: MITM",
                "[*] Tools: Loki",
                "[!] GLBP has not yet been implemented by Scapy",
                "[*] Check AVG router priority values manually using Wireshark",
                "[*] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.",
                f"[*] GLBP Sender MAC: {packet[Ether].src}",
                f"[*] GLBP Sender IP: {packet[IP].src}",
            ]
            content.append("[*] Mitigation: Use priority 255, use cryptographic authentication, filtering GLBP traffic with ACL")
            print_frame(title, content)

    # DTP
    if packet.haslayer(DTP):
        title = "Detected DTP Frame"
        content = [
            "[*] Attack Impact: VLAN Segmentation Bypass",
            "[*] Tools: Yersinia, Scapy",
            f"[*] DTP Neighbor MAC: {str(packet[Dot3].src) if packet.haslayer(Dot3) else 'Not Found'}"
        ]
        content.append("[*] Mitigation: Disable DTP")
        print_frame(title, content)

    # STP
    if packet.haslayer(STP):
        title = "Detected STP Frame"
        content = [
            "[*] Attack Impact: Partial MITM",
            "[*] Tools: Yersinia, Scapy",
            f"[*] STP Root Switch MAC: {packet[STP].rootmac}",
            f"[*] STP Root ID: {packet[STP].rootid}",
            f"[*] STP Root Path Cost: {packet[STP].pathcost}"
        ]
        content.append("[*] Mitigation: Enable BPDU Guard")
        print_frame(title, content)

    # CDP
    if packet.haslayer(CDPv2_HDR):
        title = "Detected CDP Frame"
        content = [
            "[*] Attack Impact: Information Gathering, DoS (CDP Flood)",
            "[*] Tools: Above, Wireshark, Yersinia",
            f"[*] Hostname: {str(packet[0][CDPMsgDeviceID].val.decode())}" if packet.haslayer(CDPMsgDeviceID) else "[*] Hostname: Not Found",
            f"[*] Port ID: {str(packet[0][CDPMsgPortID].iface.decode())}" if packet.haslayer(CDPMsgPortID) else "[*] Port ID: Not Found",
            f"[*] IP Address: {packet[0][CDPAddrRecordIPv4].addr if packet.haslayer(CDPAddrRecordIPv4) else 'Not Found'}"
        ]

        if packet.haslayer(CDPMsgPlatform):
            platform_info = f"[*] Platform: {str(packet[0][CDPMsgPlatform].val.decode())}"
        else:
            platform_info = "[*] Platform: Not Found"
        
        content.append(platform_info)
        content.append("[*] Mitigation: Disable CDP on endpoint ports. Do not disrupt the IP phones, be careful")
        print_frame(title, content)

    # EIGRP
    if packet.haslayer(EIGRP):
        title = "Detected EIGRP Packet"
        content = [
            "[*] Attack Impact: Subnets Discovery, Blackhole, Evil Twin",
            "[*] Tools: Loki, Scapy, FRRouting",
            f"[*] AS Number: {packet[EIGRP].asn}",
            f"[*] EIGRP Neighbor IP: {packet[IP].src if packet.haslayer(IP) else 'Not Found'}",
            f"[*] EIGRP Neighbor MAC: {packet[Ether].src if packet.haslayer(Ether) else 'Not Found'}"
        ]
        
        if packet.haslayer(EIGRPAuthData):
            content.append("[!] There is EIGRP Authentication")
            if packet[EIGRPAuthData].authtype == 2:  # MD5 Authentication
                content.append("[!] Authentication: MD5")
                content.append("[*] Tools for bruteforce: eigrp2john.py, John the Ripper")
        else:
            content.append("[!] Authentication: No")
        
        content.append("[*] Mitigation: Enable passive interfaces, use cryptographic authentication, filter EIGRP traffic with ACL")
        print_frame(title, content)

    # LLMNR
    if packet.haslayer(UDP) and packet[UDP].dport == 5355:
        title = "Detected LLMNR Packet"
        content = [
            "[*] Attack Impact: LLMNR Spoofing, Credentials Interception",
            "[*] Tools: Responder",
            "[*] LLMNR Speaker IP: Not Available", 
            "[*] LLMNR Speaker MAC: Not Available"
        ]
        if packet.haslayer(IP):
            content[-2] = f"[*] LLMNR Speaker IP: {packet[IP].src}"
        if packet.haslayer(Ether):
            content[-1] = f"[*] LLMNR Speaker MAC: {packet[Ether].src}"
        
        content.append("[*] Mitigation: Disable LLMNR with GPOs")
        print_frame(title, content)

    # NBT-NS
    if packet.haslayer(UDP) and packet[UDP].dport == 137:
        title = "Detected NBT-NS Packet"
        content = [
            "[*] Attack Impact: NBT-NS Spoofing, Credentials Interception",
            "[*] Tools: Responder"
        ]
        speaker_ip = packet[IP].src if packet.haslayer(IP) else "Not Found"
        content.append(f"[*] NBT-NS Speaker IP: {speaker_ip}")
        speaker_mac = packet[Ether].src if packet.haslayer(Ether) else "Not Found"
        content.append(f"[*] NBT-NS Speaker MAC: {speaker_mac}")

        content.append("[*] Mitigation: Disable NBT-NS with GPOs")
        print_frame(title, content)
    
    # MDNS
    if packet.haslayer(UDP) and packet[UDP].dport == 5353:
        if packet.haslayer(IP): 
            ip_src = packet[IP].src
            ip_layer = IP
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
            ip_layer = IPv6
        else:
            ip_src = "Unknown"
            ip_layer = None

        title = "Detected MDNS Packet"
        content = [
            "[*] Attack Impact: MDNS Spoofing, Credentials Interception",
            "[*] Tools: Responder",
            "[!] MDNS Spoofing works specifically against Windows machines",
            "[*] You cannot get NetNTLMv2-SSP from Apple devices",
            f"[*] MDNS Speaker IP: {ip_src}",
            f"[*] MDNS Speaker MAC: {packet[Ether].src if packet.haslayer(Ether) else 'Unknown'}"
        ]
        content.append("[*] Mitigation: Filter MDNS traffic using VACL/VMAP. Be careful with MDNS filtering, you can disrupt printers, Chromecast, etc. Monitor attacks on IDS")
        print_frame(title, content)

    # EAPOL
    if packet.haslayer(EAPOL):
        title = "Detected EAPOL Frame"
        version_info = ""
        if packet[EAPOL].version == 3:
            version_info = "802.1X-2010"      
        elif packet[EAPOL].version == 2:
            version_info = "802.1X-2004"
        elif packet[EAPOL].version == 1:
            version_info = "802.1X-2001"
        else:
            version_info = "Unknown"
        
        content = [
            f"[*] 802.1X Version: {version_info}"
        ]
        
        print_frame(title, content)

    # DHCP Discover
    if packet.haslayer(BOOTP) and packet.haslayer(DHCP):
        dhcp_layers = packet.getlayer(DHCP).fields['options']
        for option in dhcp_layers:
            if option[0] == 'message-type' and option[1] == 1:
                title = "Detected DHCP Discover Packet"
                content = [
                    f"[*] Client MAC: {packet[Ether].src}",
                    f"[*] Transaction ID: {hex(packet[BOOTP].xid)}",
                    "[*] DHCP Options:",
                ]
                for opt in dhcp_layers:
                    if opt[0] == 'end':
                        break
                    content.append(f"{opt[0]}: {opt[1]}")
                print_frame(title, content)   

    # VLAN
    if packet.haslayer(Dot1Q):
        title = "Detected 802.1Q (VLAN)"
        vlan_ids = set()
        vlan_ids.add(packet[Dot1Q].vlan)
        if len(vlan_ids) == 0:
            return
        content = [
            f"[!] Found VLAN IDs: {', '.join(str(vlan_id) for vlan_id in vlan_ids)}",
            "[*] Attack Impact: VLAN Segmentation Bypass",
            "[*] Tools: Native Linux tools",
        ]
        content.append("[*] Mitigation: Carefully check the configuration of trunk ports")
        print_frame(title, content)

# IGMP
    if packet.haslayer(IGMP):
        igmp_layer = packet[IGMP]
        src_ip = packet[IP].src if packet.haslayer(IP) else "Not Found"
        mac_src = packet[Ether].src if packet.haslayer(Ether) else "Not Found"

        content = []
        title = "IGMP Packet Detected"

        if igmp_layer.type == 0x16:  
            title = "Detected IGMPv2 Join Message"
            content = [
                "[*] Attack Impact: Could be used for multicast spoofing or unnecessary traffic generation",
                "[*] Tools: Scapy for custom packet crafting"
            ]
        elif igmp_layer.type == 0x17:
            title = "Detected IGMPv2 Leave Message"
            content = [
                "[*] Attack Impact: Could lead to denial of multicast service",
                "[*] Tools: Scapy for custom packet crafting"
            ]
        elif igmp_layer.type == 0x22:
            title = "Detected IGMPv3 Membership Report"
            content = [
                "[*] Attack Impact: Could be used for multicast spoofing or unnecessary traffic generation",
                "[*] Tools: Scapy for custom packet crafting"
            ]

        content.append("[*] IGMP Speaker IP: " + src_ip)
        content.append("[*] IGMP Speaker MAC: " + mac_src)
        content.append("[*] Mitigation: Ensure proper multicast group management and monitor for abnormal traffic patterns")

        print_frame(title, content)
    
    # ICMPv6 RS
    if packet.haslayer(ICMPv6ND_RS):
        title = "Detected ICMPv6 Router Solicitation Message"
        src_ip = packet[IPv6].src if packet.haslayer(IPv6) else "Not Found"
        dst_ip = packet[IPv6].dst if packet.haslayer(IPv6) else "Not Found"
        content = [
            f"[*] ICMPv6 Speaker IP: {src_ip}",
            f"[*] ICMPv6 Destination IP: {dst_ip}"
        ]
        print_frame(title, content)           

    # LLDP
    if packet.haslayer(LLDPDU):
        title = "Detected LLDP Frame"
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        hostname = "Unknown"
        os_version = "Unknown"
        if packet.haslayer(LLDPDUSystemName):
            hostname = packet[LLDPDUSystemName].system_name
        if packet.haslayer(LLDPDUSystemDescription):
            os_version = packet[LLDPDUSystemDescription].description
        content = [
            f"[*] Source MAC: {src_mac}",
            f"[*] Destination MAC: {dst_mac}",
            f"[*] Hostname: {hostname}",
            f"[*] OS Version: {os_version}",
        ]
        content.append("[*] Mitigation: Disable LLDP on endpoint ports")
        print_frame(title, content)

    # MNDP
    if packet.haslayer(UDP) and packet[UDP].dport == 5678:
        title = "Detected MNDP Packet"
        mndp_mac = packet[Ether].src
        mndp_ip = packet[IP].src
        content = [
            "[*] MikroTik device may have been detected",
            "[*] Attack Impact: Information Gathering",
            "[*] Tools: Wireshark",
            f"[*] MNDP Speaker MAC: {mndp_mac}",
            f"[*] MNDP Speaker IP: {mndp_ip}",
        ]
        content.append("[*] Mitigation: Disable MNDP on endpoint ports")
        print_frame(title, content)

    # DHCPv6
    if packet.haslayer(UDP) and (packet[UDP].sport == 546 or packet[UDP].dport == 546 or packet[UDP].sport == 547 or packet[UDP].dport == 547):
        title = "Detected DHCPv6 Packet"
        content = [
            "[*] Attack Impact: DNS IPv6 Spoofing",
            "[*] Tools: mitm6",
            f"[*] DHCPv6 Speaker MAC: {packet[Ether].src}" if packet.haslayer(Ether) else "[*] DHCPv6 Speaker MAC: Not Found",
            f"[*] DHCPv6 Speaker IP: {packet[IPv6].src if packet.haslayer(IPv6) else 'Not Found'}",
        ]
        content.append("[*] Mitigation: Enable RA Guard, SAVI")
        print_frame(title, content)

    # SSDP
    if packet.haslayer(UDP) and packet[UDP].dport == 1900:
        title = "Detected SSDP Packet"
        ssdp_mac = packet[Ether].src
        ssdp_ip = packet[IP].src
        content = [
            "[*] Attack Impact: SSDP Spoofing, Credentials Interception",
            "[*] Tools: evil-ssdp",
            "[*] The attack may seem too theoretical",
            "[*] SSDP Spoofing works specifically against Windows machines",
            "[*] You cannot get NetNTLMv2-SSP from Apple devices",
            f"[*] SSDP Speaker MAC: {ssdp_mac}",
            f"[*] SSDP Speaker IP: {ssdp_ip}",
        ]
        content.append("[*] Mitigation: Filter SSDP traffic using VACL/VMAP, monitor attacks on IDS")
        print_frame(title, content)

# list for packets processing
packets = []

# Passive ARP
def passive_arp_monitor(packet):
    if packet.haslayer(ARP):
        ip_addr = packet[ARP].psrc
        mac_addr = packet[ARP].hwsrc
        title = "Detected Host"
        content = [
            f"Host IP Address: {ip_addr}",
            f"Host MAC Address: {mac_addr}",
        ]
        print_frame(title, content)


# Main function, traffic sniffing, arguments
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', type=str, required=False, help='Interface to capture packets on')
    parser.add_argument('--timer', type=int, help='Time in seconds to capture packets')
    parser.add_argument('--output-pcap', type=str, help='Output filename for pcap file')
    parser.add_argument('--input-pcap', type=str, help='Path to the input PCAP file for analysis')
    parser.add_argument('--passive-arp', action='store_true', help='Host discovery (Passive ARP)')
    args = parser.parse_args()

    # print message if no arguments are entered
    if not any(vars(args).values()):
        print("[!] Use --help to work with the tool")

    if args.input_pcap:
        print("[+] Analyzing pcap file...\n")
        analyze_pcap(args.input_pcap)
    elif args.passive_arp:
        print("[+] Host discovery using Passive ARP\n")
        sniff(iface=args.interface, timeout=args.timer, prn=passive_arp_monitor, store=0)
    elif args.interface and (args.timer or args.output_pcap):
        print("[+] Start sniffing...\n")
        print("[*] After the protocol is detected - all necessary information about it will be displayed")
        print("[*] Sniffer is not recommended to run on TUN interfaces due to the use of L2 filters")
        sniff(iface=args.interface, timeout=args.timer, prn=packet_detection, store=0)

    if packets and args.output_pcap:
        try:
            wrpcap(args.output_pcap, packets)
            print(Fore.YELLOW + Style.BRIGHT + f"[*] Saved {len(packets)} packets to {args.output_pcap}")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"Error saving packets to {args.output_pcap}: {e}")

if __name__ == "__main__":
    main()