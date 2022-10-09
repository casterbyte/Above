#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.l2 import *
from scapy.contrib.ospf import *
from scapy.contrib.eigrp import *
from scapy.contrib.cdp import *
from scapy.contrib.dtp import *
from scapy.contrib.lldp import *
from scapy.layers.vrrp import *
from scapy.layers.hsrp import *
import argparse
from colorama import Fore, Style
import colorama
import subprocess
import re

colorama.init(autoreset=True)

print(Fore.LIGHTWHITE_EX + Style.BRIGHT + r"""
####################################################################################################
####################################################################################################
######P~~~!J5GB#####G~~~!YG#################B?!G##########5~~~75G#############5~~!5########G7~~Y####
######Y  .^.  .?####P  :~..:!JPB###########5:  .?B########J  :^..:!YG#########Y    !P####B7.   ?####
######Y  7&#G5JY####P. 7#BPJ~:.:!JP######G!  ?Y: :5#######Y  7#G57^..:!JP#####Y  ?J  7GBJ. 7J  ?####
######Y  :J5G#&&####P. 7##&&&G?.  !B###BJ. ~P#&B7  !G#####Y  7##&&#P!   !B####Y  7&G! .. ^5&Y  ?####
######Y  ..  .^J####P. 7&#GJ~..~JG####5^ :Y######P~ .JB###Y  ?&B57:.:!JG######Y  7###P~^Y###J  ?####
######Y  !#G5J!J####P. ^7^.:75B#######7  !B&######?  ^G###Y  ^~. :75B#########Y  7##########J  ?####
######Y  !##########P. :^. ^JG#########P^ .J####5^ .J#####Y  .~JG#############Y  7##########J  ?####
######Y  !##########P. 7#GY!. :75B#######J. ^PG7  7G######Y  7&###############Y  7##########J  ?####
######Y  !##########P. 7###&#P?. .!B######G7  . ^5########Y  7################Y  7##########J  ?####
######Y  !##########P. 7###BP?~..~?B######&P:   J#########Y  7################Y  7##########J  ?####
######Y  !##########P. !GJ~..^75B########B7  !?. ~P#######Y  7################Y  7##########J  ?####
######Y  !##########P   .:!YG##########BJ. ^5#&G!  7G#####J  7################Y  !##########J  ?####
######GYJP##########BYYYPB#############GJJYB#####5JJP#####GJJP################GJJP##########GYJP####
########&##################################################&&###################&#############&#####
####################################################################################################
""")
print(Fore.GREEN + Style.BRIGHT + "Sniff-based Network Vulnerability Scanner")
print(Fore.GREEN + Style.BRIGHT + "Author: Magama Bazarov, @in9uz, <in9uz@protonmail.com>\n")

print(Fore.WHITE + Style.BRIGHT + "To skip scanning some protocol during a full scan - hit" + Fore.BLUE + Style.BRIGHT + " CTRL + C")


# Hex to string (for OSPF plaintext password)
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value

def dhcpv6_sniff (pkt):
            dhcpv6_dst_addr = "ff02::1:2"
            if IPv6 in pkt:
                pkt[0][IPv6].dst == dhcpv6_dst_addr
                return True


# CDP Scanning
def detect_cdp(interface, timeout):
    print (Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the CDP protocol...")
    cdp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not cdp_frame:
        print (Fore.RED + Style.BRIGHT + "[!] Error. CDP isn't detected.")
        return 0
    snapcode = cdp_frame[0][SNAP].code
    if snapcode == 0x2000:
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable CDP")
        print (Fore.LIGHTCYAN_EX + Style.BRIGHT + "[*] Impact: Information Gathering, DoS Attack via CDP Flooding")
        print (Fore.LIGHTMAGENTA_EX + Style.BRIGHT + "[*] Tools: Yersinia, Wireshark")
        cdphostname = cdp_frame[0][CDPMsgDeviceID].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Hostname is: " + Fore.BLUE + Style.BRIGHT + str(cdphostname.decode()))
        cdphardwareversion = cdp_frame[0][CDPMsgSoftwareVersion].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Target Version: " + Fore.BLUE + Style.BRIGHT + str(cdphardwareversion.decode()))
        cdphardwareplatform = cdp_frame[0][CDPMsgPlatform].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Target Platform: " + Fore.BLUE + Style.BRIGHT + str(cdphardwareplatform.decode()))
        cdpportid = cdp_frame[0][CDPMsgPortID].iface
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Your port: " + Fore.BLUE + Style.BRIGHT + str(cdpportid.decode()))
        if cdp_frame[0].haslayer(CDPAddrRecordIPv4):
            cdpaddr = cdp_frame[0][CDPAddrRecordIPv4].addr  
            print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Target IP Address: " + Fore.BLUE + Style.BRIGHT + cdpaddr)
    if snapcode == 0x2004:
        print (Fore.RED  + "[!] Detected DTP. Skipping... Run the script again!")


# LLDP Scanning
def detect_lldp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLDP protocol...")
    lldp_frame = sniff(filter="ether dst 01:80:c2:00:00:0e", count=1, timeout=args.timeout, iface=args.interface)
    if not lldp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. LLDP isn't detected.")
        return 0
    else:
        print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable LLDP")
        print(Fore.CYAN + Style.BRIGHT + "[*] Impact: Information Gathering")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Wireshark")
        lldp_port_id = lldp_frame[0][LLDPDUPortDescription].description
        lldp_system_name = lldp_frame[0][LLDPDUSystemName].system_name
        lldp_description = lldp_frame[0][LLDPDUSystemDescription].description
        print(Fore.YELLOW + Style.BRIGHT + "[*] Your Port ID : " + Fore.BLUE + Style.BRIGHT + str(lldp_port_id.decode()))
        print(Fore.YELLOW + Style.BRIGHT + "[*] Target Hostname : " + Fore.BLUE + Style.BRIGHT + str(lldp_system_name.decode()))
        print(Fore.YELLOW + Style.BRIGHT + "[*] Target OS Version : " + Fore.BLUE + Style.BRIGHT + str(lldp_description.decode()))


# DTP Scanning
def detect_dtp(interface, timeout):
    print (Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the DTP protocol...")
    dtp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not dtp_frame:
        print (Fore.RED + Style.BRIGHT + "[!] Error. DTP isn't detected.")
        return 0
    dtp_snapcode = dtp_frame[0][SNAP].code
    if dtp_snapcode == 0x2004:
        dtp_neighbor = dtp_frame[0][DTPNeighbor].neighbor
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable DTP")
        print (Fore.CYAN + Style.BRIGHT + "[*] Impact: VLAN Segmenation Bypassing")
        print (Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Yersinia, Scapy")
        print (Fore.YELLOW + Style.BRIGHT + "[*] DTP Neighbor is : " + Fore.BLUE + Style.BRIGHT + str(dtp_neighbor))
    if dtp_snapcode == 0x2000:
        print (Fore.RED  + "[!] Detected CDP. Skipping... Run the script again!")


# OSPF Scanning
def detect_ospf(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the OSPF protocol...")
    ospfpacket = sniff(filter="ip dst 224.0.0.5", count=1, iface=args.interface, timeout=args.timeout)
    if not ospfpacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. OSPF isn't detected.")
        return 0
    areaID = ospfpacket[0][OSPF_Hdr].area
    authtype = ospfpacket[0][OSPF_Hdr].authtype
    ospfkeyid = ospfpacket[0][OSPF_Hdr].keyid
    authdatalength = ospfpacket[0][OSPF_Hdr].authdatalen
    authseq = ospfpacket[0][OSPF_Hdr].seq
    hellosource = ospfpacket[0][OSPF_Hdr].src
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable OSPF. Here is a little information about the autonomous system")
    print(Fore.CYAN + Style.BRIGHT + "[*] Impact: Network Intelligence, MITM, DoS, Blackhole.")
    print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Loki, Scapy, FRRouting")
    print(Fore.YELLOW + Style.BRIGHT + "[*] Your OSPF area ID: " + Fore.BLUE + Style.BRIGHT + str(areaID))
    print(Fore.YELLOW + Style.BRIGHT + "[*] Your OSPF Neighbor: " + Fore.BLUE + Style.BRIGHT + str(hellosource))
    # Null Auth
    if authtype == 0x0:
        print(Fore.YELLOW + Style.BRIGHT + "[!] OSPF Authentication " + Fore.BLUE + Style.BRIGHT + "isn't used.")
    # Simple Auth (Plaintext)
    if authtype == 0x1:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Simple OSPF Authentication " + Fore.BLUE + Style.BRIGHT + "is used")
        raw = ospfpacket[0][OSPF_Hdr].authdata
        hex_value = hex(raw)
        string = hex_to_string(hex_value)
        print(Fore.YELLOW + Style.BRIGHT + "[*] Plaintext Password: " + Fore.BLUE + Style.BRIGHT + string)
    # Crypt Auth (MD5)
    if authtype == 0x02:
        print(Fore.YELLOW + Style.BRIGHT + "[!] MD5 Auth " + Fore.BLUE + Style.BRIGHT + "is detected. " + Fore.YELLOW + Style.BRIGHT + "Bruteforce it.")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Ettercap, John the Ripper")
        print(Fore.YELLOW + Style.BRIGHT + "[*] OSPF Key ID is: " + Fore.BLUE + Style.BRIGHT + str(ospfkeyid))
        print(Fore.YELLOW + Style.BRIGHT + "[*] Crypt data length: " + Fore.BLUE + Style.BRIGHT + str(authdatalength))
        print(Fore.YELLOW + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.BLUE + Style.BRIGHT + str(authseq))


# EIGRP Scanning
def detect_eigrp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the EIGRP protocol...")
    eigrppacket = sniff(filter="ip dst 224.0.0.10", count=1, timeout=args.timeout, iface=args.interface)
    if not eigrppacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. EIGRP isn't detected.")
        return 0
    else:
        print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected EIGRP. Here is a little information about the autonomous system")
        print(Fore.CYAN + Style.BRIGHT + "[*] Impact: Network Intelligence, MITM, DoS, Blackhole.")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Loki, Scapy, FRRouting")
    asnumber = eigrppacket[0][EIGRP].asn
    if eigrppacket[0].haslayer("EIGRPAuthData"):
        print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
    eigrpneighborip = eigrppacket[0][IP].src
    print(Fore.YELLOW + Style.BRIGHT + "[*] Your AS Number is " + Fore.BLUE + Style.BRIGHT + str(asnumber))
    print(Fore.YELLOW + Style.BRIGHT + "[*] Your EIGRP Neighbor is " + Fore.BLUE + Style.BRIGHT + str(eigrpneighborip))


# HSRPv1 Scanning
def detect_hsrpv1(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the HSRPv1 protocol...")
    # waiting five HSRP frames for test
    hsrpv1_packet = sniff(count=5, filter="ip dst 224.0.0.2", iface=args.interface, timeout=args.timeout)
    if not hsrpv1_packet:
        print (Fore.RED + Style.BRIGHT + "[!] Error. HSRPv1 isn't detected.")
        return 0
    if hsrpv1_packet[0][HSRP].state == 16 and hsrpv1_packet[0][HSRP].priority < 255:
            print ("[*] Info: Detected vulnerable HSRP value of ACTIVE Router")
            hsrpv1senderip = hsrpv1_packet[0][IP].src
            hsrpv1sendermac = hsrpv1_packet[0][Ether].src
            hsrpv1priority = hsrpv1_packet[1][HSRP].priority
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender Value: " + Fore.BLUE + Style.BRIGHT + str(hsrpv1priority))         
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender IP: " + Fore.BLUE + Style.BRIGHT + hsrpv1senderip)
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender MAC: " + Fore.BLUE + Style.BRIGHT + hsrpv1sendermac)
            if hsrpv1_packet[0].haslayer(HSRPmd5):
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                print (Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            if hsrpv1_packet[0][HSRP].auth:
                print ("[!] Simple HSRP Authentication is used.")
                hsrpv1_plaintext = hsrpv1_packet[0][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print ("[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
            return 0 
    if hsrpv1_packet[1][HSRP].state == 16 and hsrpv1_packet[1][HSRP].priority < 255:
            print ("[*] Info: Detected vulnerable HSRP value of ACTIVE Router")
            hsrpv1senderip = hsrpv1_packet[1][IP].src
            hsrpv1sendermac = hsrpv1_packet[1][Ether].src
            hsrpv1priority = hsrpv1_packet[1][HSRP].priority
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 ACTIVE Sender Value: " + Fore.BLUE + Style.BRIGHT + str(hsrpv1priority))    
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender IP: " + Fore.BLUE + Style.BRIGHT + hsrpv1senderip)
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender MAC: " + Fore.BLUE + Style.BRIGHT + hsrpv1sendermac)
            if hsrpv1_packet[1].haslayer(HSRPmd5):
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                print (Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            if hsrpv1_packet[1][HSRP].auth:
                print (Fore.YELLOW + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
                hsrpv1_plaintext = hsrpv1_packet[1][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
            return 0 
    if hsrpv1_packet[2][HSRP].state == 16 and hsrpv1_packet[2][HSRP].priority < 255:
            print ("[*] Info: Detected vulnerable HSRP value of ACTIVE Router")
            hsrpv1senderip = hsrpv1_packet[2][IP].src
            hsrpv1sendermac = hsrpv1_packet[2][Ether].src
            hsrpv1priority = hsrpv1_packet[2][HSRP].priority
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 ACTIVE Sender Value: " + Fore.BLUE + Style.BRIGHT + str(hsrpv1priority))    
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender IP: " + Fore.BLUE + Style.BRIGHT + hsrpv1senderip)
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender MAC: " + Fore.BLUE + Style.BRIGHT + hsrpv1sendermac)
            if hsrpv1_packet[2].haslayer(HSRPmd5):
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                print (Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            if hsrpv1_packet[2][HSRP].auth:
                print (Fore.YELLOW + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
                hsrpv1_plaintext = hsrpv1_packet[2][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
            return 0 
    if  hsrpv1_packet[3][HSRP].state == 16 and hsrpv1_packet[3][HSRP].priority < 255:
            print ("[*] Info: Detected vulnerable HSRP value of ACTIVE Router")
            hsrpv1senderip = hsrpv1_packet[3][IP].src
            hsrpv1sendermac = hsrpv1_packet[3][Ether].src
            hsrpv1priority = hsrpv1_packet[3][HSRP].priority
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 ACTIVE Sender Value: " + Fore.BLUE + Style.BRIGHT + str(hsrpv1priority))    
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender IP: " + Fore.BLUE + Style.BRIGHT + hsrpv1senderip)
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 Sender MAC: " + Fore.BLUE + Style.BRIGHT + hsrpv1sendermac)
            if hsrpv1_packet[3].haslayer(HSRPmd5):
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                print (Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            if hsrpv1_packet[3][HSRP].auth:
                print (Fore.YELLOW + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
                hsrpv1_plaintext = hsrpv1_packet[3][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
            return 0 
    if  hsrpv1_packet[4][HSRP].state == 16 and hsrpv1_packet[4][HSRP].priority < 255:
            print ("[*] Info: Detected vulnerable HSRP value of ACTIVE Router")
            hsrpv1senderip = hsrpv1_packet[4][IP].src
            hsrpv1sendermac = hsrpv1_packet[4][Ether].src
            hsrpv1priority = hsrpv1_packet[4][HSRP].priority
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv1 ACTIVE Sender Value: " + Fore.BLUE + Style.BRIGHT + str(hsrpv1priority))    
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv2 Sender IP: " + Fore.BLUE + Style.BRIGHT + hsrpv1senderip)
            print(Fore.YELLOW + Style.BRIGHT + "[*] HSRPv2 Sender MAC: " + Fore.BLUE + Style.BRIGHT + hsrpv1sendermac)
            if hsrpv1_packet[4].haslayer(HSRPmd5):
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                print (Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
            if hsrpv1_packet[4][HSRP].auth:
                print (Fore.YELLOW + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
                hsrpv1_plaintext = hsrpv1_packet[4][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print (Fore.YELLOW + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
            return 0

# VRRP Scanning
def detect_vrrp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the VRRP protocol...")
    vrrppacket = sniff(filter="ip dst 224.0.0.18", count=1, timeout=args.timeout, iface=args.interface)
    if not vrrppacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. VRRP isn't detected.")
        return 0
    else:
        vrrppriority = vrrppacket[0][VRRP].priority
        vrrpauthtype = vrrppacket[0][VRRP].authtype
        ipsrcpacket = vrrppacket[0][IP].src
        vrrpmacsender = vrrppacket[0][Ether].src
        if vrrpauthtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP Authentication is not used")
        if vrrpauthtype == 0x1:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Plaintext VRRP Authentication is used. Check this on Wireshark")
        if vrrpauthtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[*] VRRP MD5 Auth is used")
        if vrrppriority <= 255:
            print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable VRRP Value")
            print(Fore.CYAN + Style.BRIGHT + "[*] Impact: MITM")
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Scapy, Loki")
    print(Fore.YELLOW + Style.BRIGHT + "[*] VRRP Sender IP: " + Fore.BLUE + Style.BRIGHT + ipsrcpacket)
    print(Fore.YELLOW + Style.BRIGHT + "[*] VRRP Sender MAC: " + Fore.BLUE + Style.BRIGHT + vrrpmacsender)



# STP Scanning
def detect_stp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the STP protocol...")
    stp_frame = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, timeout=args.timeout, iface=args.interface)
    if not stp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. STP isn't detected.")
        return 0
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "[*] Info: Detected vulnerable STP")
    print(Fore.CYAN + Style.BRIGHT + "[*] Impact: MITM, VLAN ID Gathering. Check Root Bridge System ID Extension header in STP frame")
    print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Yersinia, Wireshark")
    stp_root_mac = stp_frame[0][STP].rootmac
    stp_root_id = stp_frame[0][STP].rootid
    stp_root_pathcost = stp_frame[0][STP].pathcost
    print(Fore.YELLOW + Style.BRIGHT + "[*] STP Root MAC: " + Fore.BLUE + Style.BRIGHT + str(stp_root_mac))
    print(Fore.YELLOW + Style.BRIGHT + "[*] STP Root ID: " + Fore.BLUE + Style.BRIGHT + str(stp_root_id))
    print(Fore.YELLOW + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.BLUE + Style.BRIGHT + str(stp_root_pathcost))


# LLMNR Scanning
def detect_llmnr(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLMNR protocol...")
    llmnr_packet = sniff(filter="ip dst 224.0.0.252", count=1, timeout=args.timeout, iface=args.interface)
    if not llmnr_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. LLMNR isn't detected.")
        return 0
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Info: Detected LLMNR.")
        print(Fore.CYAN + Style.BRIGHT + "[*] Impact: LLMNR Poisoning Attack (Stealing NetNTLM hashes, Possible SMB/HTTP/NTLM/LDAP Relay Attack)")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Responder")
        llmnr_sender_mac = llmnr_packet[0][Ether].src
        llmnr_sender_ip = llmnr_packet[0][IP].src
        print(Fore.YELLOW + Style.BRIGHT + "[*] LLMNR Sender IP: " + Fore.BLUE + Style.BRIGHT + str(llmnr_sender_ip))
        print(Fore.YELLOW + Style.BRIGHT + "[*] LLMNR Sender MAC: " + Fore.BLUE + Style.BRIGHT + str(llmnr_sender_mac))



# NBT-NS Scanning
def detect_nbns(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the NBT-NS protocol...")
    nbns_packet = sniff(filter="udp and port 137", count=1, timeout=args.timeout, iface=args.interface)
    if not nbns_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. NBT-NS isn't detected.")
        return 0
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Info: Detected NBT-NS protocol.")
        print(Fore.CYAN + Style.BRIGHT + "[*] Impact: NBT-NS Poisoning Attack (Stealing NetNTLM hashes, Possible SMB/HTTP/NTLM/LDAP Relay Attack)")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: Responder")
        nbns_sender_mac = nbns_packet[0][Ether].src
        nbns_sender_ip = nbns_packet[0][IP].src
        print(Fore.YELLOW + Style.BRIGHT + "[*] NBT-NS Sender IP: " + Fore.BLUE + Style.BRIGHT + str(nbns_sender_ip))
        print(Fore.YELLOW + Style.BRIGHT + "[*] NBT-NS Sender MAC: " + Fore.BLUE + Style.BRIGHT + str(nbns_sender_mac))

# DHCPv6 Scanning
def detect_dhcpv6(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the DHCPv6 protocol...")
    dhcpv6_packet = sniff(count = 1,lfilter=dhcpv6_sniff, iface=args.interface, timeout=args.timeout)
    if not dhcpv6_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. DHCPv6 isn't detected.")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Info: Detected DHCPv6 request.")
        print(Fore.CYAN + Style.BRIGHT + "[*] Impact: DNS Spoofing over IPv6 Attack (Stealing NetNTLM hashes/NTLM Relay)")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Tools: mitm6")
        dhcpv6_mac_address_sender = dhcpv6_packet[0][Ether].src
        dhcpv6_packet_sender = dhcpv6_packet[0][IPv6].src
        print(Fore.YELLOW + Style.BRIGHT + "[*] DHCPv6 Request Sender IP: " + Fore.BLUE + Style.BRIGHT + dhcpv6_packet_sender)
        print(Fore.YELLOW + Style.BRIGHT + "[*] DHCPv6 Request Sender MAC: " + Fore.BLUE + Style.BRIGHT + dhcpv6_mac_address_sender)
        return 0

def switch_to_promisc(interface):
    print(Fore.YELLOW + Style.BRIGHT + "\n[!] Switching " + Fore.BLUE + Style.BRIGHT + interface + Fore.YELLOW + Style.BRIGHT + " to promiscious mode")
    subprocess.call(["ip", "link", "set", interface, "promisc", "on"])
    ip_a_result = subprocess.check_output(["ip", "add", "show", interface])
    promisc_mode_search = re.search(r"PROMISC", ip_a_result.decode())
    if promisc_mode_search:
        print (Fore.YELLOW + Style.BRIGHT + "[*] Switched " + Fore.BLUE + Style.BRIGHT + "successfully")
    else:
        print (Fore.RED + Style.BRIGHT + "[!] Error. Not switched to promisc.")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", dest="interface", type=str, required=True, help="Specify your interface")
    parser.add_argument("--timeout", dest="timeout", type=int, required=True, help="Specify the timeout. How much time to sniff")
    parser.add_argument("--cdp", dest="cdp",  action='store_true', help="CDP Scan")
    parser.add_argument("--dtp", dest="dtp",  action='store_true', help="DTP Scan")
    parser.add_argument("--lldp", dest="lldp", action='store_true', help="LLDP Scan")
    parser.add_argument("--ospf", dest="ospf", action='store_true', help="OSPF Scan")
    parser.add_argument("--eigrp", dest="eigrp",  action='store_true', help="EIGRP Scan")
    parser.add_argument("--vrrp", dest="vrrp",  action='store_true', help="VRRP Scan")
    parser.add_argument("--hsrpv1", dest="hsrpv1", action='store_true', help="HSRPv1 Scan")
    parser.add_argument("--stp", dest="stp",  action='store_true', help="STP Scan")
    parser.add_argument("--llmnr", dest="llmnr",  action='store_true', help="LLMNR Scan")
    parser.add_argument("--nbns", dest="nbns",  action='store_true', help="NBNS Scan")
    parser.add_argument("--dhcpv6", dest="dhcpv6", action='store_true', help="DHCPv6 Scan")
    parser.add_argument("--fullscan", dest="fullscan", action='store_true', help="Scan all protocols")

    args = parser.parse_args()

switch_to_promisc(args.interface)

if args.cdp or args.fullscan:
    detect_cdp(args.interface, args.timeout)

if args.dtp or args.fullscan:
    detect_dtp(args.interface, args.timeout)

if args.lldp or args.fullscan:
    detect_lldp(args.interface, args.timeout)

if args.ospf or args.fullscan:
    detect_ospf(args.interface, args.timeout)

if args.eigrp or args.fullscan:
    detect_eigrp(args.interface, args.timeout)

if args.vrrp or args.fullscan:
    detect_vrrp(args.interface, args.timeout)

if args.hsrpv1 or args.fullscan:
    detect_hsrpv1(args.interface, args.timeout)

if args.stp or args.fullscan:
    detect_stp(args.interface, args.timeout)

if args.llmnr or args.fullscan:
    detect_llmnr(args.interface, args.timeout)

if args.nbns or args.fullscan:
    detect_nbns(args.interface, args.timeout)

if args.dhcpv6 or args.fullscan:
    detect_dhcpv6(args.interface, args.timeout)