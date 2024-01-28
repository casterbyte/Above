#!/usr/bin/env python3

from scapy.all import sniff, wrpcap, Ether, Dot1Q, IP, HSRP, HSRPmd5, VRRP, VRRPv3, STP, IPv6, AH, SNAP, LLMNRQuery, Dot3
from scapy.contrib.eigrp import EIGRP
from scapy.contrib.ospf import OSPF_Hdr
from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4
from scapy.contrib.lldp import LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID, LLDPDUManagementAddress # Connecting only the necessary Scapy components
import colorama
from colorama import Fore, Style
import threading
import shutil
import argparse
import signal
import socket
import sys
from pcap_analyzer import analyze_pcap

# CAUTION: The whole program consists of many functions. 14 threads are used for simultaneous analysis of all protocols
# There's a lot of uses for print
# A lot of try & except loops


colorama.init(autoreset=True)

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
print(centered_text(Fore.YELLOW + "Version 2.3, Codename: Radiant"))
print(centered_text(Fore.YELLOW + "Author: Magama Bazarov, <cursed@exploit.org>"))


# CDP Detection
def detect_cdp(interface, timer, output_file):
    cdp_detected = False # Flag to track if CDP frame has been detected
    while True:
        cdp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=timer, iface=interface)
        if not cdp_frame:
            return 0
        if output_file:
            save_to_pcap(cdp_frame, output_file)
        if cdp_frame[0][SNAP].code == 0x2000 and not cdp_detected:
            cdp_detected = True  # Set the flag to True to indicate that CDP frame has been detected
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected CDP Protocol")
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Information Gathering, DoS (CDP Flood)")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Above, Wireshark, Yersinia")
            print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + str(cdp_frame[0][CDPMsgDeviceID].val.decode()))
            print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + str(cdp_frame[0][CDPMsgSoftwareVersion].val.decode()))
            print(Fore.GREEN + Style.BRIGHT + "[*] Platform: " + Fore.WHITE + Style.BRIGHT + str(cdp_frame[0][CDPMsgPlatform].val.decode()))
            print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + str(cdp_frame[0][CDPMsgPortID].iface.decode()))
            try:
                print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + cdp_frame[0][CDPAddrRecordIPv4].addr)
            except:
                print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")
            # Mitigation
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable CDP on endpoint ports. Do not disrupt the IP phones, be careful")
        
# DTP Detection
def detect_dtp(interface, timer, output_file):
    dtp_detected = False  # Flag to track if DTP frame has been detected
    while True:
        dtp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, iface=interface, timeout=timer)
        if not dtp_frame:
            return 0
        if output_file:
            save_to_pcap(dtp_frame, output_file)
        if dtp_frame[0][SNAP].code == 0x2004 and not dtp_detected:
            dtp_detected = True  # Set the flag to True to indicate that DTP frame has been detected
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected DTP Protocol")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.WHITE + Style.BRIGHT + "VLAN Segmentation Bypass")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
            print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(dtp_frame[0][Dot3].src))
            # Mitigation
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable DTP on the switch ports")

# LLDP Detection
def detect_lldp(interface, timer, output_file):
    lldp_frame = sniff(filter="ether dst 01:80:c2:00:00:0e", count=1, timeout=timer, iface=interface)
    if not lldp_frame:
        return 0
    if output_file:
        save_to_pcap(lldp_frame, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLDP Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Information Gathering")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Above, Wireshark")
    try:
        print (Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + str(lldp_frame[0][LLDPDUSystemName].system_name.decode()))
    except:
        print (Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    try:
        print (Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + str(lldp_frame[0][LLDPDUSystemDescription].description.decode()))
    except:
        print (Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    try:
        print (Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + str(lldp_frame[0][LLDPDUPortID].id.decode()))
    except:
        print (Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    try:
        lldp_mgmt_address_bytes = lldp_frame[0][LLDPDUManagementAddress].management_address
        decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes) # decode ip address
        print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + decoded_mgmt_address)
    except:
        print (Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLDP on endpoint ports. Do not disrupt the IP phones, be careful")
    
# 802.1Q Tags
def detect_dot1q(interface, timer):
    # To search for unique IDs without duplication
    vlan_ids = set()
    # Custom Filter
    def sniff_dot1q(pkt):
        if pkt.haslayer(Dot1Q):
            vlan_ids.add(pkt[Dot1Q].vlan)

    sniff(iface=interface, prn=sniff_dot1q, timeout=timer)
    if len(vlan_ids) == 0:
        return
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected 802.1Q Tags")
    print(Fore.GREEN + Style.BRIGHT + "[+] Found VLAN IDs:" + Fore.WHITE + Style.BRIGHT + f" {', '.join(str(vlan_id) for vlan_id in vlan_ids)}")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "VLAN Segmentation Bypass")
    print(Fore.YELLOW + Style.BRIGHT + "[!] Using the IDs found, create the necessary virtual interfaces using Linux tools")
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Carefully check the configuration of trunk ports")
    
# OSPF Detection
def detect_ospf(interface, timer, output_file):
    ospfpacket = sniff(filter="ip dst 224.0.0.5 and ip proto 89", count=1, iface=interface, timeout=timer)
    if not ospfpacket:
        return 0
    if output_file:
        save_to_pcap(ospfpacket, output_file)

    # For display cleartext string (simple OSPF auth)
    def hex_to_string(hex):
        if hex[:2] == '0x':
            hex = hex[2:]
        string_value = bytes.fromhex(hex).decode('utf-8')
        return string_value
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected OSPF Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
    print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Area ID: " + Fore.WHITE + Style.BRIGHT + str(ospfpacket[0][OSPF_Hdr].area))
    print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(ospfpacket[0][OSPF_Hdr].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(ospfpacket[0][Ether].src))
    # No Auth
    if ospfpacket[0][OSPF_Hdr].authtype == 0x0:
        print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
    # Plaintext Auth
    if ospfpacket[0][OSPF_Hdr].authtype == 0x1:
        raw = ospfpacket[0][OSPF_Hdr].authdata
        hex_value = hex(raw)
        string = hex_to_string(hex_value)
        print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.YELLOW + Style.BRIGHT + "Plaintext Phrase: " + string)
    # Crypt Auth (MD5)
    if ospfpacket[0][OSPF_Hdr].authtype == 0x02:
        print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
        print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: Ettercap, John the Ripper")
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.WHITE + Style.BRIGHT + str(ospfpacket[0][OSPF_Hdr].keyid))
        print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Data Length: " + Fore.WHITE + Style.BRIGHT + str(authdatalength = ospfpacket[0][OSPF_Hdr].authdatalen))
        print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.WHITE + Style.BRIGHT + str(ospfpacket[0][OSPF_Hdr].seq))
    # Mitigation    
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use cryptographic authentication, filter OSPF traffic with ACLs")
    
# EIGRP Detection
def detect_eigrp(interface, timer, output_file):
    eigrppacket = sniff(filter="ip dst 224.0.0.10 and ip proto 88", count=1, timeout=timer, iface=interface)
    if not eigrppacket:
        return 0
    else:
        if output_file:
            save_to_pcap(eigrppacket, output_file)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EIGRP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
    if eigrppacket[0].haslayer("EIGRPAuthData"):
        print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
        if eigrppacket[0]["EIGRP"]["EIGRP Authentication Data"].authtype == 2:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools for bruteforce: " + Fore.WHITE + Style.BRIGHT + "eigrp2john.py, John the Ripper")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
    print(Fore.GREEN + Style.BRIGHT + "[*] AS Number: " + Fore.WHITE + Style.BRIGHT + str(eigrppacket[0][EIGRP].asn))
    print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(eigrppacket[0][IP].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(eigrppacket[0][Ether].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use cryptographic authentication, filter EIGRP traffic with ACLs")
    
# HSRP Detection
def detect_hsrp(interface, timer, output_file):
    # HSRP version 1 (224.0.0.2 & UDP/1985)
    hsrp_detected = False  # Flag to track if HSRP packet with state 16 has been detected
    while True:
        hsrp_packet = sniff(count=1, filter="ip dst 224.0.0.2 and udp port 1985", iface=interface, timeout=timer)
        if not hsrp_packet:
            return 0
        if output_file:
            save_to_pcap(hsrp_packet, output_file)
        if hsrp_packet[0][HSRP].state == 16 and hsrp_packet[0][HSRP].priority < 255 and not hsrp_detected:
            hsrp_detected = True  # Set the flag to True to indicate that HSRP packet with state 16 has been detected
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRP Protocol")
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP active router priority: " + Fore.WHITE + Style.BRIGHT + str((hsrp_packet[0].priority)))
            print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, Yersinia")
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(hsrp_packet[0][HSRP].group))
            print(Fore.GREEN + Style.BRIGHT + "[+] HSRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(hsrp_packet[0][HSRP].virtualIP))
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(hsrp_packet[0][IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(hsrp_packet[0][Ether].src))
            if hsrp_packet[0].haslayer(HSRPmd5):
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
                print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            else:
                if hsrp_packet[0][HSRP].auth:
                    hsrpv1_plaintext = hsrp_packet[0][HSRP].auth # capture password on the variable
                    simplehsrppass = hsrpv1_plaintext.decode("UTF-8") # decoding to utf-8
                    print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext Phrase: " + simplehsrppass)
            # Mitigation        
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use cryptographic authentication, filtering HSRP traffic with ACLs")
            
# VRRP Detection (v2 & v3)
def detect_vrrp(interface, timer, output_file):
    vrrp_packet = sniff(filter="ip dst 224.0.0.18 or ip proto 112", count=1, timeout=timer, iface=interface)
    if not vrrp_packet:
        return 0
    else:
        if output_file:
            save_to_pcap(vrrp_packet, output_file)
        if vrrp_packet[0].haslayer(AH): # Detect AH Authentication
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Protocol") 
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "AH")
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][Ether].src))
            print(Fore.YELLOW + Style.BRIGHT + "[*] If this router is running RouterOS and AH is active - at this time, bruteforcing AH hashes from RouterOS is considered impossible")
            print(Fore.YELLOW + Style.BRIGHT + "[*] If it is keepalived, there is no problem with bruteforcing the AH hash")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Unfortunately at the moment there is no tool that sends VRRP packets with AH authentication support")
            return 0
        # VRRPv3 Detection
        if vrrp_packet[0].haslayer(VRRPv3):
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv3 Protocol")
            if vrrp_packet[0][VRRPv3].priority <= 255: # The problem is that usually the configuration does not allow you to set the priority to 255 on the hardware, only 254.
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 master router priority: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRPv3].priority))
                print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "MITM")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Group Number: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRPv3].vrid))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][IP].src))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][Ether].src))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRPv3].addrlist))
                print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter VRRP traffic using ACLs/FW")
                return 0
        # VRRPv2 Detection
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Protocol")
        if vrrp_packet[0][VRRP].priority <= 255: # The problem is that usually the configuration does not allow you to set the priority to 255 on the hardware, only 254.
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 master router priority: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRP].priority))
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        # VRRP Null Auth    
        if vrrp_packet[0][VRRP].authtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        # VRRP Plaintext Auth    
        if vrrp_packet[0][VRRP].authtype == 0x1:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext. Look at the password in Wireshark")
        # VRRP Cryptographic Auth    
        if vrrp_packet[0][VRRP].authtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Group Number: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRP].vrid))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][Ether].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(vrrp_packet[0][VRRP].addrlist))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use cryptographic authentication, filter VRRP traffic using ACLs")
        
# STP Detection
def detect_stp(interface, timer, output_file):
    stp_frame = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, timeout=timer, iface=interface)
    if not stp_frame:
        return 0
    if output_file:
        save_to_pcap(stp_frame, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected STP Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Partial MITM")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
    print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Switch MAC: " + Fore.WHITE + Style.BRIGHT + str(stp_frame[0][STP].rootmac))
    print(Fore.GREEN + Style.BRIGHT + "[*] STP Root ID: " + Fore.WHITE + Style.BRIGHT + str(stp_frame[0][STP].rootid))
    print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.WHITE + Style.BRIGHT + str(stp_frame[0][STP].pathcost))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable BPDU Guard")
    
# LLMNR Detection
def detect_llmnr(interface, timer, output_file):
    llmnr_packet = sniff(filter="ip dst 224.0.0.252 and udp port 5355", count=1, timeout=timer, iface=interface)
    if not llmnr_packet:
        return 0
    if output_file:
        save_to_pcap(llmnr_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLMNR Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "LLMNR Spoofing, Credentials Interception")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
    try:
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + str(llmnr_packet[0][LLMNRQuery]["DNS Question Record"].qname.decode()))
    except:
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    try:
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(llmnr_packet[0][LLMNRQuery].id))
    except:
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(llmnr_packet[0][IP].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(llmnr_packet[0][Ether].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLMNR with GPOs")
        
# NBT-NS Detection
def detect_nbns(interface, timer, output_file):
    # NBNS uses broadcast
    nbns_packet = sniff(filter="ether dst ff:ff:ff:ff:ff:ff and udp port 137", count=1, timeout=timer, iface=interface)
    if not nbns_packet:
        return 0
    if output_file:
        save_to_pcap(nbns_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected NBT-NS Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "NBT-NS Spoofing, Credentials Interception")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
    try:
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet[0]["NBNS registration request"].QUESTION_NAME.decode()))
    except:
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    try:
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet[0]["NBNS Header"].NAME_TRN_ID))
    except:
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet[0][IP].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet[0][Ether].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable NBT-NS with GPOs")
         
# MDNS Detection
def detect_mdns(interface, timer, output_file):
    mdns_packet = sniff(filter="ip dst 224.0.0.251 and udp port 5353", count=1, timeout=timer, iface=interface)
    if not mdns_packet:
        return 0
    if output_file:
        save_to_pcap(mdns_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected MDNS Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "MDNS Spoofing, Credentials Interception")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
    # There is no Query Name output here because at the time of Above v2.3 - Scapy does not know how to handle MDNS packets
    print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(mdns_packet[0][IP].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(mdns_packet[0][Ether].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter MDNS traffic using VACL/VMAP. Be careful with MDNS filtering, you can disrupt printers, Chromecast, etc. Monitor attacks on IDS")       
        
# DHCPv6 Detection
def detect_dhcpv6(interface, timer, output_file):
    dhcpv6_packet = sniff(filter="udp and port 546 and port 547", count=1, iface=interface, timeout=timer)
    if not dhcpv6_packet:
        return 0
    if output_file:
        save_to_pcap(dhcpv6_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCPv6 Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "DNS IPv6 Spoofing")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "mitm6")
    print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(dhcpv6_packet[0][IPv6].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(dhcpv6_packet[0][Ether].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable RA Guard, SAVI")
        
# SSDP Detection
def detect_ssdp(interface, timer, output_file):
    ssdp_packet = sniff(filter="ip dst 239.255.255.250 and udp port 1900", count=1, timeout=timer, iface=interface)
    if not ssdp_packet:
        return 0
    if output_file:
        save_to_pcap(ssdp_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected SSDP Protocol")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Credentials Interception, MITM")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "evil-ssdp")
    print(Fore.GREEN + Style.BRIGHT + "[!] The attack may seem too theoretical")
    print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(ssdp_packet[0][Ether].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(ssdp_packet[0][IP].src))
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter SSDP traffic using VACL/VMAP, monitor attacks on IDS")

def detect_mndp(interface, timer, output_file):
    mndp_packet = sniff(filter="ip dst 255.255.255.255 and udp port 5678", count=1, timeout=timer, iface=interface)
    if not mndp_packet:
        return 0
    if output_file:
        save_to_pcap(mndp_packet, output_file)
    print(Fore.WHITE + Style.BRIGHT + '-' * 50)
    print(Fore.WHITE + Style.BRIGHT + "[+] Detected MNDP Protocol")
    print(Fore.WHITE + Style.BRIGHT + "[*] MikroTik device may have been detected")
    print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.WHITE + Style.BRIGHT + "Information Gathering")
    print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark")
    print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(mndp_packet[0][Ether].src))
    print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(mndp_packet[0][IP].src))
    print(Fore.YELLOW + Style.BRIGHT + "[*] You can get more information from the packet in Wireshark")
    print(Fore.YELLOW + Style.BRIGHT + "[*] The MNDP protocol is not yet implemented in Scapy")
    # Mitigation
    print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable MNDP on endpoint ports")
    
        
output_lock = threading.Lock()
exit_flag = False
output_message_displayed = False

# Recording traffic to pcap file
def save_to_pcap(packet, output_file):
    global output_message_displayed
    with output_lock:
        try:
            wrpcap(output_file, packet, append=True)
            if not output_message_displayed:
                print(Fore.YELLOW + f"[*] The detected protocols are recorded in {output_file}")
                output_message_displayed = True
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"Error saving to pcap: {e}")
            

# To interrupt the code by pressing CTRL + C
def signal_handler(sig, frame):
    global exit_flag
    print("\n[!] CTRL + C is pressed. Exiting...")
    exit_flag = True
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# Protocols sniffing, threads
def start_sniffing(interface, timer, output_file):
    print(Fore.WHITE + "\n[+] Start Sniffing...")
    print(Fore.WHITE + "\n[+] Searching for L2/L3 Protocols...")
    print(Fore.WHITE +"[*] The specified timer applies to all protocols")
    print(Fore.GREEN + "[*] After the protocol is detected - all necessary information about it will be displayed")
    cdp_thread = threading.Thread(target=detect_cdp, args=(interface, timer, output_file))
    dtp_thread = threading.Thread(target=detect_dtp, args=(interface, timer, output_file))
    lldp_thread = threading.Thread(target=detect_lldp, args=(interface, timer, output_file))
    dot1q_thread = threading.Thread(target=detect_dot1q, args=(interface, timer))
    ospf_thread = threading.Thread(target=detect_ospf, args=(interface, timer, output_file))
    eigrp_thread = threading.Thread(target=detect_eigrp, args=(interface, timer, output_file))
    hsrp_thread = threading.Thread(target=detect_hsrp, args=(interface, timer, output_file))
    vrrp_thread = threading.Thread(target=detect_vrrp, args=(interface, timer, output_file))
    stp_thread = threading.Thread(target=detect_stp, args=(interface, timer, output_file))
    llmnr_thread = threading.Thread(target=detect_llmnr, args=(interface, timer, output_file))
    nbns_thread = threading.Thread(target=detect_nbns, args=(interface, timer, output_file))
    mdns_thread = threading.Thread(target=detect_mdns, args=(interface, timer, output_file))
    dhcpv6_thread = threading.Thread(target=detect_dhcpv6, args=(interface, timer, output_file))
    ssdp_thread = threading.Thread(target=detect_ssdp, args=(interface, timer, output_file))
    mndp_thread = threading.Thread(target=detect_mndp, args=(interface, timer, output_file))

    threads = [cdp_thread, dtp_thread, lldp_thread, dot1q_thread, ospf_thread, eigrp_thread, hsrp_thread,
    vrrp_thread, stp_thread, llmnr_thread, nbns_thread, mdns_thread, dhcpv6_thread, ssdp_thread, mndp_thread]
        
    for thread in threads:
        thread.daemon = True
        thread.start()

    for thread in threads:
        thread.join()

# Main function, args parsing
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", dest="interface", type=str, required=None, help="Specify the interface")
    parser.add_argument("--timer", dest="timer", type=int, required=None, help="Specify the timer value (seconds)")
    parser.add_argument("--output-pcap", dest="output_file", type=str, required=None, help="Specify the output pcap file to record traffic (hot mode)")
    parser.add_argument("--input-pcap", dest="input_file", type=str, required=None, help="Specify the input pcap file to analyze traffic (cold mode)")
    args = parser.parse_args()

    # print message if no arguments are entered
    if not any(vars(args).values()):
        print("[!] Use --help to work with the tool")
        
    # pcap analysis (cold mode)
    if args.input_file:
        print("\n[+] Start analyzing pcap file...")
        analyze_pcap(args.input_file)
    # traffic sniffing (hot mode)
    elif args.interface and (args.timer or args.output_file):
        start_sniffing(args.interface, args.timer, args.output_file)

if __name__ == "__main__":
    main()
