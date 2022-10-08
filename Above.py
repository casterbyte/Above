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

colorama.init(autoreset=True)

print(Fore.WHITE + r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗    
██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔════╝    
███████║██████╔╝██║   ██║██║   ██║█████╗      
██╔══██║██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝      
██║  ██║██████╔╝╚██████╔╝ ╚████╔╝ ███████╗    
╚═╝  ╚═╝╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝  
""")
print(Fore.WHITE + Style.BRIGHT + "Sniff-based Network Vulnerability Scanner")
print(Fore.WHITE + Style.BRIGHT + "Author: Magama Bazarov, @in9uz, <in9uz@protonmail.com>\n")


# Hex to string (for OSPF plaintext password)
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value


# CDP Scanning
def detect_cdp(interface, timeout):
    print (Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the CDP protocol...")
    cdp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not cdp_frame:
        print (Fore.RED + Style.BRIGHT + "Error. CDP isn't detected.")
        return 0
    snapcode = cdp_frame[0][SNAP].code
    if snapcode == 0x2000:
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable CDP")
        print (Fore.LIGHTCYAN_EX + Style.BRIGHT + "Impact: Information Gathering, DoS Attack via CDP Flooding")
        print (Fore.LIGHTMAGENTA_EX + Style.BRIGHT + "Tools: Yersinia, Wireshark")
        cdphostname = cdp_frame[0][CDPMsgDeviceID].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Hostname is: " + Fore.BLUE + Style.BRIGHT + str(cdphostname.decode()))
        cdphardwareversion = cdp_frame[0][CDPMsgSoftwareVersion].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Target Version: " + Fore.BLUE + Style.BRIGHT + str(cdphardwareversion.decode()))
        cdphardwareplatform = cdp_frame[0][CDPMsgPlatform].val
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Target Platform: " + Fore.BLUE + Style.BRIGHT + str(cdphardwareplatform.decode()))
        cdpportid = cdp_frame[0][CDPMsgPortID].iface
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Your port: " + Fore.BLUE + Style.BRIGHT + str(cdpportid.decode()))
        if cdp_frame[0].haslayer(CDPAddrRecordIPv4):
            cdpaddr = cdp_frame[0][CDPAddrRecordIPv4].addr  
            print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Target IP Address: " + Fore.BLUE + Style.BRIGHT + cdpaddr)
    if snapcode == 0x2004:
        print (Fore.RED  + "Detected DTP. Skipping... Run the script again!")


# LLDP Scanning
def detect_lldp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLDP protocol...")
    lldp_frame = sniff(filter="ether dst 01:80:c2:00:00:0e", count=1, timeout=args.timeout, iface=args.interface)
    if not lldp_frame:
        print(Fore.RED + Style.BRIGHT + "Error. LLDP isn't detected.")
        return 0
    else:
        print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable LLDP")
        print(Fore.CYAN + Style.BRIGHT + "Impact: Information Gathering")
        print(Fore.MAGENTA + Style.BRIGHT + "Tools: Wireshark")
        lldp_port_id = lldp_frame[0][LLDPDUPortDescription].description
        lldp_system_name = lldp_frame[0][LLDPDUSystemName].system_name
        lldp_description = lldp_frame[0][LLDPDUSystemDescription].description
        print(Fore.YELLOW + Style.BRIGHT + "Your Port ID : " + Fore.BLUE + Style.BRIGHT + str(lldp_port_id.decode()))
        print(Fore.YELLOW + Style.BRIGHT + "Target Hostname : " + Fore.BLUE + Style.BRIGHT + str(lldp_system_name.decode()))
        print(Fore.YELLOW + Style.BRIGHT + "Target OS Version : " + Fore.BLUE + Style.BRIGHT + str(lldp_description.decode()))


# DTP Scanning
def detect_dtp(interface, timeout):
    print (Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the DTP protocol...")
    dtp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not dtp_frame:
        print (Fore.RED + Style.BRIGHT + "Error. DTP isn't detected.")
        return 0
    dtp_snapcode = dtp_frame[0][SNAP].code
    if dtp_snapcode == 0x2004:
        dtp_neighbor = dtp_frame[0][DTPNeighbor].neighbor
        print (Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable DTP")
        print (Fore.CYAN + Style.BRIGHT + "Impact: VLAN Segmenation Bypassing")
        print (Fore.MAGENTA + Style.BRIGHT + "Tools: Yersinia, Scapy")
        print (Fore.YELLOW + Style.BRIGHT + "DTP Neighbor is : " + str(dtp_neighbor))
    if dtp_snapcode == 0x2000:
        print (Fore.RED  + "Detected CDP. Skipping... Run the script again!")


# OSPF Scanning
def detect_ospf(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the OSPF protocol...")
    ospfpacket = sniff(filter="ip dst 224.0.0.5", count=1, iface=args.interface, timeout=args.timeout)
    if not ospfpacket:
        print(Fore.RED + Style.BRIGHT + "Error. OSPF isn't detected.")
        return 0
    areaID = ospfpacket[0][OSPF_Hdr].area
    authtype = ospfpacket[0][OSPF_Hdr].authtype
    ospfkeyid = ospfpacket[0][OSPF_Hdr].keyid
    authdatalength = ospfpacket[0][OSPF_Hdr].authdatalen
    authseq = ospfpacket[0][OSPF_Hdr].seq
    hellosource = ospfpacket[0][OSPF_Hdr].src
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable OSPF. Here is a little information about the autonomous system")
    print(Fore.CYAN + Style.BRIGHT + "Impact: Network Intelligence, MITM, DoS, Blackhole.")
    print(Fore.MAGENTA + Style.BRIGHT + "Tools: Loki, Scapy, FRRouting")
    print(Fore.YELLOW + Style.BRIGHT + "Your OSPF area ID: " + Fore.BLUE + Style.BRIGHT + str(areaID))
    print(Fore.YELLOW + Style.BRIGHT + "Your OSPF Neighbor: " + Fore.BLUE + Style.BRIGHT + str(hellosource))
    # Null Auth
    if authtype == 0x0:
        print(Fore.YELLOW + Style.BRIGHT + "OSPF Authentication isn't used.")
    # Simple Auth (Plaintext)
    if authtype == 0x1:
        print(Fore.YELLOW + Style.BRIGHT + "Simple OSPF Authentication " + Fore.BLUE + Style.BRIGHT + "is used")
        raw = ospfpacket[0][OSPF_Hdr].authdata
        hex_value = hex(raw)
        string = hex_to_string(hex_value)
        print(Fore.YELLOW + Style.BRIGHT + "Plaintext Password: " + Fore.BLUE + Style.BRIGHT + string)
    # Crypt Auth (MD5)
    if authtype == 0x02:
        print(Fore.YELLOW + Style.BRIGHT + "MD5 Auth is detected. Bruteforce it.")
        print(Fore.MAGENTA + Style.BRIGHT + "Tools: Ettercap, John the Ripper")
        print(Fore.YELLOW + Style.BRIGHT + "OSPF Key ID is: " + str(ospfkeyid))
        print(Fore.YELLOW + Style.BRIGHT + "Crypt data length: " + str(authdatalength))
        print(Fore.YELLOW + Style.BRIGHT + "Crypt Auth Sequence Number: " + str(authseq))


# EIGRP Scanning
def detect_eigrp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the EIGRP protocol...")
    eigrppacket = sniff(filter="ip dst 224.0.0.10", count=1, timeout=args.timeout, iface=args.interface)
    if not eigrppacket:
        print(Fore.RED + Style.BRIGHT + "Error. EIGRP isn't detected.")
        return 0
    else:
        print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected EIGRP. Here is a little information about the autonomous system")
        print(Fore.CYAN + Style.BRIGHT + "Impact: Network Intelligence, MITM, DoS, Blackhole.")
        print(Fore.MAGENTA + Style.BRIGHT + "Tools: Loki, Scapy, FRRouting")
    asnumber = eigrppacket[0][EIGRP].asn
    if eigrppacket[0].haslayer("EIGRPAuthData"):
        print("There is EIGRP Authentication")
    eigrpneighborip = eigrppacket[0][IP].src
    print(Fore.YELLOW + Style.BRIGHT + "Your AS Number is " + Fore.BLUE + Style.BRIGHT + str(asnumber))
    print(Fore.YELLOW + Style.BRIGHT + "Your EIGRP Neighbor is " + Fore.BLUE + Style.BRIGHT + str(eigrpneighborip))


# VRRP Scanning
def detect_vrrp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the VRRP protocol...")
    vrrppacket = sniff(filter="ip dst 224.0.0.18", count=1, timeout=args.timeout, iface=args.interface)
    if not vrrppacket:
        print(Fore.RED + Style.BRIGHT + "Error. VRRP isn't detected.")
        return 0
    else:
        vrrppriority = vrrppacket[0][VRRP].priority
        vrrpauthtype = vrrppacket[0][VRRP].authtype
        ipsrcpacket = vrrppacket[0][IP].src
        if vrrpauthtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "VRRP Authentication is not used")
        if vrrpauthtype == 0x1:
            print(Fore.YELLOW + Style.BRIGHT + "Plaintext VRRP Authentication is used. Check this on Wireshark")
        if vrrpauthtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "VRRP MD5 Auth is used")
        if vrrppriority <= 255:
            print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable VRRP")
            print(Fore.CYAN + Style.BRIGHT + "Impact: MITM")
            print(Fore.MAGENTA + Style.BRIGHT + "Tools: Scapy, Loki")
    print(Fore.YELLOW + Style.BRIGHT + "VRRP Sender IP: " + str(ipsrcpacket))


# STP Scanning
def detect_stp(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the STP protocol...")
    stp_frame = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, timeout=args.timeout, iface=args.interface)
    if not stp_frame:
        print(Fore.RED + Style.BRIGHT + "Error. STP isn't detected.")
        return 0
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Info: Detected vulnerable STP")
    print(Fore.CYAN + Style.BRIGHT + "Impact: MITM, VLAN ID Gathering. Check Root Bridge System ID Extension header in STP frame")
    print(Fore.MAGENTA + Style.BRIGHT + "Tools: Yersinia, Wireshark")
    stp_root_mac = stp_frame[0][STP].rootmac
    stp_root_id = stp_frame[0][STP].rootid
    stp_root_pathcost = stp_frame[0][STP].pathcost
    print(Fore.YELLOW + Style.BRIGHT + "STP Root MAC: " + str(stp_root_mac))
    print(Fore.YELLOW + Style.BRIGHT + "STP Root ID: " + str(stp_root_id))
    print(Fore.YELLOW + Style.BRIGHT + "STP Root Path Cost: " + str(stp_root_pathcost))


# LLMNR Scanning
def detect_llmnr(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLMNR protocol...")
    llmnr_packet = sniff(filter="ip dst 224.0.0.252", count=1, timeout=args.timeout, iface=args.interface)
    if not llmnr_packet:
        print(Fore.RED + Style.BRIGHT + "Error. LLMNR isn't detected.")
        return 0
    else:
        print(Fore.YELLOW + Style.BRIGHT + "Info: Detected LLMNR.")
        print(Fore.CYAN + Style.BRIGHT + "Impact: LLMNR Poisoning Attack (Stealing NetNTLM hashes)")
        print(Fore.MAGENTA + Style.BRIGHT + "Tools: Responder")
        llmnr_sender_ip = llmnr_packet[0][IP].src
        print(Fore.YELLOW + Style.BRIGHT + "LLMNR Sender IP: " + str(llmnr_sender_ip))


# NBT-NS Scanning
def detect_nbns(interface, timeout):
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the NBT-NS protocol...")
    nbns_packet = sniff(filter="udp and port 137", count=1, timeout=args.timeout, iface=args.interface)
    if not nbns_packet:
        print(Fore.RED + Style.BRIGHT + "Error. NBT-NS isn't detected.")
        return 0
    else:
        print(Fore.YELLOW + Style.BRIGHT + "Info: Detected NBT-NS protocol.")
        print(Fore.CYAN + Style.BRIGHT + "Impact: NBT-NS Poisoning Attack (Stealing NetNTLM hashes)")
        print(Fore.MAGENTA + Style.BRIGHT + "Tools: Responder")
        nbns_sender_ip = nbns_packet[0][IP].src
        print(Fore.YELLOW + Style.BRIGHT + "NBT-NS Sender IP: " + str(nbns_sender_ip))


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
    parser.add_argument("--stp", dest="stp",  action='store_true', help="STP Scan")
    parser.add_argument("--llmnr", dest="llmnr",  action='store_true', help="LLMNR Scan")
    parser.add_argument("--nbns", dest="nbns",  action='store_true', help="Scan NetBIOS Name Service")
    parser.add_argument("--fullscan", dest="fullscan", action='store_true', help="Scan all protocols")
    args = parser.parse_args()

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

if args.stp or args.fullscan:
    detect_stp(args.interface, args.timeout)

if args.llmnr or args.fullscan:
    detect_llmnr(args.interface, args.timeout)

if args.nbns or args.fullscan:
    detect_nbns(args.interface, args.timeout)

    
