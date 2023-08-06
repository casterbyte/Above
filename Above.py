#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.ospf import *
from scapy.contrib.eigrp import *
from scapy.contrib.cdp import *
from scapy.contrib.dtp import *
from scapy.layers.hsrp import *
from scapy.layers.l2 import *
import argparse
import colorama
from colorama import Fore, Style
from scapy.contrib.macsec import MACsecSCI
import subprocess
import re
import pyshark
import shutil
import requests

colorama.init(autoreset=True)

text = r"""
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
"""

terminal_width = shutil.get_terminal_size().columns

for line in text.split("\n"):
    padding = " " * ((terminal_width - len(line)) // 2)
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + padding + line)


def centered_text(text, color=Fore.WHITE, style=Style.BRIGHT):
    terminal_width = shutil.get_terminal_size().columns
    padding = " " * ((terminal_width - len(text)) // 2)
    return f"{color}{style}{padding}{text}"


print(centered_text("Network Vulnerability Scanner", Fore.WHITE))
print(centered_text("Author: Caster, @wearecaster, <casterinfosec@gmail.com>", Fore.RED))


# MAC Address Checker (ft. macaddress.io)
def resolve_mac_address(mac_address):
    api_key = "at_fdSVq1okmEVuCYWZR3Taix1kpUH6T"
    url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={mac_address}"
    response = requests.get(url)
    if response.ok:
        data = response.json()
        return data.get("vendorDetails", {}).get("companyName")


# MACSec Filter
def is_macsec_packet(packet):
    return packet.haslayer(Ether) and packet[Ether].type == 0x88E5

# MACSec Scanning
def detect_macsec():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the MACSec...")
    macsec_frame = sniff(count=1, iface=args.interface, timeout=args.timeout, lfilter=is_macsec_packet)
    if not macsec_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. MACSec not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info: " + Fore.YELLOW + Style.BRIGHT + "Detected MACSec")
        print(Fore.YELLOW + Style.BRIGHT + "[!] You can try to bypass MACSec")
        macsec_sci_identifier = macsec_frame[0].SCI.system_identifier
        print(Fore.GREEN + Style.BRIGHT + "[*] MACSec SCI Identifier: " + Fore.YELLOW + Style.BRIGHT + str(
            macsec_sci_identifier))
        if args.resolve_mac:
            mac_from_macsec_frame = macsec_frame[0].eth.src
            macinfo = resolve_mac_address(mac_from_macsec_frame)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# CDP Scanning
def detect_cdp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the CDP protocol...")
    cdp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not cdp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. CDP isn't detected.")
        return 0
    snapcode = cdp_frame[0][SNAP].code
    if snapcode == 0x2000:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected CDP")
        print(
            Fore.GREEN + Style.BRIGHT + "[!] Impact:" + Fore.YELLOW + Style.BRIGHT + " Information Gathering, CDP Flooding")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Yersinia, Scapy, Wireshark")
        cdphostname = cdp_frame[0]['Device ID'].val
        print(Fore.GREEN + Style.BRIGHT + "[!] System Name: " + Fore.YELLOW + Style.BRIGHT + str(cdphostname.decode()))
        cdphardwareversion = cdp_frame[0]['Software Version'].val
        print(Fore.GREEN + Style.BRIGHT + "[*] Device Version: " + Fore.YELLOW + Style.BRIGHT + str(
            cdphardwareversion.decode()))
        cdphardwareplatform = cdp_frame[0]['Platform'].val
        print(Fore.GREEN + Style.BRIGHT + "[*] Device Platform: " + Fore.YELLOW + Style.BRIGHT + str(
            cdphardwareplatform.decode()))
        cdpportid = cdp_frame[0]['Port ID'].iface
        print(Fore.GREEN + Style.BRIGHT + "[!] Device Port: " + Fore.YELLOW + Style.BRIGHT + str(cdpportid.decode()))
        if cdp_frame[0].haslayer(CDPAddrRecordIPv4):
            cdpaddr = cdp_frame[0][CDPAddrRecordIPv4].addr
            print(Fore.GREEN + Style.BRIGHT + "[!] CDP Device IP Address: " + Fore.YELLOW + Style.BRIGHT + cdpaddr)
    if snapcode == 0x2004:
        print(Fore.RED + "[!] Detected DTP. Skipping... Run the CDP scan again!")
    if args.resolve_mac:
        mac_from_cdp_frame = cdp_frame[0].src
        macinfo = resolve_mac_address(mac_from_cdp_frame)
        print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# LLDP Scanning
def detect_lldp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the LLDP protocol...")
    lldp_frame = pyshark.LiveCapture(interface=args.interface, bpf_filter="ether host 01:80:c2:00:00:0e")
    lldp_frame.sniff(timeout=args.timeout, packet_count=1)
    if not lldp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. LLDP isn't detected.")
        return 0
    print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected LLDP")
    if lldp_frame[0].lldp.tlv_system_name:
        lldp_hostname = lldp_frame[0].lldp.tlv_system_name
        print(Fore.GREEN + Style.BRIGHT + "[*] Device System Name: " + Fore.YELLOW + Style.BRIGHT + lldp_hostname)
    if lldp_frame[0].lldp.port_desc:
        lldp_port_id = lldp_frame[0].lldp.port_desc
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.YELLOW + Style.BRIGHT + lldp_port_id)
    if lldp_frame[0].lldp.tlv_system_desc:
        lldp_os_ver = lldp_frame[0].lldp.tlv_system_desc
        print(Fore.GREEN + Style.BRIGHT + "[*] Device OS Version: " + Fore.YELLOW + Style.BRIGHT + lldp_os_ver)
    if args.resolve_mac:
        mac_from_lldp_frame = lldp_frame[0].eth.src
        macinfo = resolve_mac_address(mac_from_lldp_frame)
        print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# DTP Scanning
def detect_dtp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the DTP protocol...")
    dtp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=args.timeout, iface=args.interface)
    if not dtp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. DTP isn't detected.")
        return 0
    else:
        dtp_snapcode = dtp_frame[0][SNAP].code
        if dtp_snapcode == 0x2004:
            dtp_neighbor = dtp_frame[0][DTPNeighbor].neighbor
            print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected DTP")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " VLAN Segmenation Bypass")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Yersinia, Scapy")
            print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.YELLOW + Style.BRIGHT + dtp_neighbor)
        if dtp_snapcode == 0x2000:
            print(Fore.RED + "[!] Detected CDP. Skipping... Run the CDP Scan again!")
        if args.resolve_mac:
            mac_from_dtp_frame = dtp_frame[0].src
            macinfo = resolve_mac_address(mac_from_dtp_frame)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# MNDP Scanning
def detect_mndp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the MNDP protocol...")
    mndp_capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="ip host 255.255.255.255 and udp port 5678")
    mndp_capture.sniff(timeout=args.timeout, packet_count=1)
    if not mndp_capture:
        print(Fore.RED + Style.BRIGHT + "[!] Error. MNDP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected MNDP")
        mndpidentity = mndp_capture[0].mndp.identity
        mndpmodel = mndp_capture[0].mndp.board
        mndpplatform = mndp_capture[0].mndp.platform
        mndposversion = mndp_capture[0].mndp.version
        mndpuptime = mndp_capture[0].mndp.uptime
        print(Fore.GREEN + Style.BRIGHT + "[*] Identity: " + Fore.YELLOW + Style.BRIGHT + mndpidentity)
        if mndp_capture[0].mndp.board:
            mndpboard = mndp_capture[0].mndp.board
            print(Fore.GREEN + Style.BRIGHT + "[*] Board Name: " + Fore.YELLOW + Style.BRIGHT + mndpboard)
        if mndp_capture[0].mndp.interfacename:
            mndpintname = mndp_capture[0].mndp.interfacename
            print(Fore.GREEN + Style.BRIGHT + "[*] Interface Name: " + Fore.YELLOW + Style.BRIGHT + mndpintname)
        if mndp_capture[0].mndp.softwareid:
            mndpsoftidinfo = mndp_capture[0].mndp.softwareid
            print(Fore.GREEN + Style.BRIGHT + "[*] Software ID: " + Fore.YELLOW + Style.BRIGHT + mndpsoftidinfo)
        #if mndp_capture[0].mndp.ipv4address:
        try:
            mndpipv4addr = mndp_capture[0].mndp.ipv4address
        except:
            mndpipv4addr = mndp_capture[0].ip.src
        print(Fore.GREEN + Style.BRIGHT + "[*] Device IP Address: " + Fore.YELLOW + Style.BRIGHT + mndpipv4addr)
        if mndp_capture[0].mndp.mac:
            mndpmac = mndp_capture[0].mndp.mac
            print(Fore.GREEN + Style.BRIGHT + "[*] Device MAC Address: " + Fore.YELLOW + Style.BRIGHT + mndpmac)
        print(Fore.GREEN + Style.BRIGHT + "[*] Device Model: " + Fore.YELLOW + Style.BRIGHT + mndpmodel)
        print(Fore.GREEN + Style.BRIGHT + "[*] Platform: " + Fore.YELLOW + Style.BRIGHT + mndpplatform)
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.YELLOW + Style.BRIGHT + mndposversion)
        print(Fore.GREEN + Style.BRIGHT + "[*] Device Uptime: " + Fore.YELLOW + Style.BRIGHT + mndpuptime)
        if args.resolve_mac:
            mac_from_mndp_frame = mndp_capture[0].eth.src
            macinfo = resolve_mac_address(mac_from_mndp_frame)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


def detect_edp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the EDP protocol...")
    edp_capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="ether host 00:e0:2b:00:00:00")
    edp_capture.sniff(timeout=args.timeout, packet_count=1)
    if not edp_capture:
        print(Fore.RED + Style.BRIGHT + "[!] Error. EDP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected EDP")
        if edp_capture[0].edp.version:
            edpver = edp_capture[0].edp.version
            print(Fore.GREEN + Style.BRIGHT + "[*] EDP Version: " + Fore.YELLOW + Style.BRIGHT + edpver)
        if edp_capture[0].edp.midmac:
            edpmidmac = edp_capture[0].edp.midmac
            print(Fore.GREEN + Style.BRIGHT + "[*] MAC: " + Fore.YELLOW + Style.BRIGHT + edpmidmac)
        if edp_capture[0].edp.info_slot:
            edpinfoslot = edp_capture[0].edp.info_slot
            print(Fore.GREEN + Style.BRIGHT + "[*] Slot Number: " + Fore.YELLOW + Style.BRIGHT + edpinfoslot)
        if edp_capture[0].edp.info_port:
            edpinfoport = edp_capture[0].edp.info_port
            print(Fore.GREEN + Style.BRIGHT + "[*] Port Number: " + Fore.YELLOW + Style.BRIGHT + edpinfoport)
        if edp_capture[0].edp.display_string:
            edpdisplaystring = edp_capture[0].edp.display_string
            print(
                Fore.GREEN + Style.BRIGHT + "[*] Device System Name: " + Fore.YELLOW + Style.BRIGHT + edpdisplaystring)
        if args.resolve_mac:
            mac_from_edp_frame = edp_capture[0].eth.src
            macinfo = resolve_mac_address(mac_from_edp_frame)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


def detect_esrp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the ESRP protocol...")
    esrp_capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="ether host 00:e0:2b:00:00:02")
    esrp_capture.sniff(timeout=args.timeout, packet_count=5)
    if not esrp_capture:
        print(Fore.RED + Style.BRIGHT + "[!] Error. ESRP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + "Detected ESRP")
        firstesrpstate = int(esrp_capture[0].edp.esrp_state)
        secondesrpstate = int(esrp_capture[1].edp.esrp_state)
        thirdesrpstate = int(esrp_capture[2].edp.esrp_state)
        fouresrpstate = int(esrp_capture[3].edp.esrp_state)
        fiveesrpstate = int(esrp_capture[4].edp.esrp_state)
        firstesrpprio = int(esrp_capture[0].edp.esrp_prio)
        secondesrpprio = int(esrp_capture[1].edp.esrp_prio)
        thirdesrpprio = int(esrp_capture[2].edp.esrp_prio)
        fouresrpprio = int(esrp_capture[3].edp.esrp_prio)
        fiveesrpprio = int(esrp_capture[4].edp.esrp_prio)
        esrpvirtualip = esrp_capture[0].edp.esrp_virtip
        print(Fore.GREEN + Style.BRIGHT + "[*] ESRP Virtual IP Address: ", Fore.YELLOW + Style.BRIGHT + esrpvirtualip)
        # ESRP Priority and States checking. . .
        if firstesrpstate or secondesrpstate or thirdesrpstate or fouresrpstate or fiveesrpstate == 1 and firstesrpprio and secondesrpprio \
                and thirdesrpprio and fouresrpprio and fiveesrpprio < 255:
            print(
                Fore.YELLOW + Style.BRIGHT + "[*] Detected vulnerable ESRP Confinguration. Vector for ESRP Hijacking Attack.")
            print(
                Fore.YELLOW + Style.BRIGHT + "[!] There are currently no tools to attack ESRP. Use this message as a network security alert.")
        else:
            print(Fore.RED + Style.BRIGHT + "ESRP is not vulnerable")
        if args.resolve_mac:
            mac_from_esrp_frame = esrp_capture[0].eth.src
            macinfo = resolve_mac_address(mac_from_esrp_frame)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# PVST Scanning
def detect_pvst():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the PVST protocol...")
    pvst_capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="ether host 01:00:0c:cc:cc:cd")
    pvst_capture.sniff(timeout=args.timeout, packet_count=1)
    if not pvst_capture:
        print(Fore.RED + Style.BRIGHT + "[!] Error. PVST not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected PVST")
        pvstvlan = pvst_capture[0].stp.pvst_origvlan
        pvstrootpriority = pvst_capture[0].stp.root_prio
        pvstrootpathcost = pvst_capture[0].stp.root_cost
        print(Fore.GREEN + Style.BRIGHT + "VLAN ID: ", Fore.YELLOW + Style.BRIGHT + pvstvlan)
        print(Fore.GREEN + Style.BRIGHT + "PVST Root Priority: ", Fore.YELLOW + Style.BRIGHT + pvstrootpriority)
        print(Fore.GREEN + Style.BRIGHT + "PVST Root Path Cost: " + Fore.YELLOW + Style.BRIGHT + pvstrootpathcost)
        if args.resolve_mac:
            mac_from_pvst_capture = pvst_capture[0].eth.src
            macinfo = resolve_mac_address(mac_from_pvst_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)


# GLBP Scanning
def detect_glbp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the GLBP protocol...")
    glbp_capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="ip host 224.0.0.102 and udp port 3222")
    glbp_capture.sniff(timeout=args.timeout, packet_count=5)
    if not glbp_capture:
        print(Fore.RED + Style.BRIGHT + "[!] Error. GLBP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + "Detected GLBP")
        firstglbpstate = glbp_capture[0].glbp.hello_vgstate
        secondglbpstate = glbp_capture[1].glbp.hello_vgstate
        thirdglbpstate = glbp_capture[2].glbp.hello_vgstate
        fourglbpstate = glbp_capture[3].glbp.hello_vgstate
        fiveglbpstate = glbp_capture[4].glbp.hello_vgstate
        firstglbpprio = glbp_capture[0].glbp.hello_priority
        secondglbpprio = glbp_capture[1].glbp.hello_priority
        thirdglbpprio = glbp_capture[2].glbp.hello_priority
        fourglbpprio = glbp_capture[3].glbp.hello_priority
        fiveglbpprio = glbp_capture[4].glbp.hello_priority
        glbp_group_number = glbp_capture[0].glbp.group
        glbp_virtual_ip = glbp_capture[0].glbp.hello_virtualipv4
        # GLBP State and GLBP Priority Checking...
        if firstglbpstate or secondglbpstate or thirdglbpstate or fourglbpstate or fiveglbpstate == 32 and firstglbpprio and secondglbpprio and \
                thirdglbpprio and fourglbpprio and fiveglbpprio < 255:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Detected vulnerable GLBP AVG/AVF priority values")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, DoS, Blackhole")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki")
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Group Number: " + Fore.YELLOW + Style.BRIGHT + str(
                glbp_group_number))
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + str(
                glbp_virtual_ip))
        else:
            print(Fore.RED + Style.BRIGHT + "GLBP is not vulnerable")
            # GLBP Authentication checking
            if hasattr(glbp_capture[0], 'glbp'):
                field_names = glbp_capture[0].glbp._all_fields
                if 'glbp.auth.authtype' in field_names:
                    print(
                        Fore.RED + Style.BRIGHT + "[!] GLBP Authentication detected. There is not yet a tool that works with GLBP authentication. An attack is not possible at this time")
                    glbpauthtype = int(glbp_capture[0].glbp.auth_authtype)
                    # GLBP MD5 Auth checking
                    if glbpauthtype == 2:
                        print(glbpauthtype)
                        print(Fore.RED + Style.BRIGHT + "GLBP MD5 Authentication detected")
                    # GLBP Plaintext
                    if glbpauthtype == 1:
                        print(Fore.RED + Style.BRIGHT + "GLBP Plaintext Authentication detected")
                        plainpass = glbp_capture[0].glbp.auth_plainpass
                        print(Fore.RED + Style.BRIGHT + plainpass)
        if args.resolve_mac:
            mac_from_glbp_capture = glbp_capture[0].eth.src
            macinfo = resolve_mac_address(mac_from_glbp_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            return 0


def detect_hsrp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the HSRP protocol...")
    hsrpv1_packet = sniff(count=5, filter="udp and host 224.0.0.2", iface=args.interface, timeout=args.timeout)
    if not hsrpv1_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. HSRP not detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected HSRP")
        first_hsrp_state = hsrpv1_packet[0][HSRP].state
        second_hsrp_state = hsrpv1_packet[1][HSRP].state
        third_hsrp_state = hsrpv1_packet[2][HSRP].state
        four_hsrp_state = hsrpv1_packet[3][HSRP].state
        five_hsrp_state = hsrpv1_packet[4][HSRP].state
        first_hsrp_prio = hsrpv1_packet[0][HSRP].priority
        second_hsrp_prio = hsrpv1_packet[1][HSRP].priority
        third_hsrp_prio = hsrpv1_packet[2][HSRP].priority
        four_hsrp_prio = hsrpv1_packet[3][HSRP].priority
        five_hsrp_prio = hsrpv1_packet[4][HSRP].priority
        hsrp_group_number = hsrpv1_packet[0][HSRP].group
        hsrp_virt_ip = hsrpv1_packet[0][HSRP].virtualIP
        if first_hsrp_state or second_hsrp_state or third_hsrp_state or four_hsrp_state or five_hsrp_state == 16 and first_hsrp_prio \
                and second_hsrp_prio and third_hsrp_prio and four_hsrp_prio and five_hsrp_prio < 255:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Detected vulnerable HSRP priority values")
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.YELLOW + Style.BRIGHT + str(
                hsrp_group_number))
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + str(
                hsrp_virt_ip))
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, Dos, Blackhole")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki")
        else:
            print(Fore.RED + Style.BRIGHT + "HSRP is not vulnerable")
        if hsrpv1_packet[0][HSRP].auth == b'cisco\x00\x00\x00':
            print(Fore.WHITE + Style.BRIGHT + "[!] Simple HSRP Authentication is used.")
            hsrpv1_plaintext = hsrpv1_packet[0][HSRP].auth
            simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
            print(Fore.WHITE + Style.BRIGHT + "[!] HSRP Plaintext Password: " + Fore.BLUE + Style.BRIGHT + simplehsrppass)
        if hsrpv1_packet[0][HSRP][HSRPmd5]:
            print(Fore.YELLOW + Style.BRIGHT + "[!] HSRP MD5 Authentication is used. You can bruteforce it.")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Tools for bruteforce: hsrp2john.py, John the Ripper")
        if args.resolve_mac:
            mac_from_hsrp_capture = hsrpv1_packet[0].src
            macinfo = resolve_mac_address(mac_from_hsrp_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            return 0


# Hex to string (For OSPF plaintext password)
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value

# OSPF Scanning
def detect_ospf():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the OSPF protocol...")
    ospfpacket = sniff(filter="ip dst 224.0.0.5", count=1,
                       iface=args.interface, timeout=args.timeout)
    if not ospfpacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. OSPF isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected OSPF")
        areaID = ospfpacket[0][OSPF_Hdr].area
        authtype = ospfpacket[0][OSPF_Hdr].authtype
        ospfkeyid = ospfpacket[0][OSPF_Hdr].keyid
        authdatalength = ospfpacket[0][OSPF_Hdr].authdatalen
        authseq = ospfpacket[0][OSPF_Hdr].seq
        hellosource = ospfpacket[0][OSPF_Hdr].src
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " Network Intelligence, MITM, DoS, Blackhole.")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] Your OSPF area ID: " + Fore.YELLOW + Style.BRIGHT + str(areaID))
        print(Fore.GREEN + Style.BRIGHT + "[*] Your OSPF Neighbor: " + Fore.YELLOW + Style.BRIGHT + str(hellosource))
        # Null Auth
        if authtype == 0x0:
            print(Fore.GREEN + Style.BRIGHT + "[!] OSPF Authentication " + Fore.YELLOW + Style.BRIGHT + "isn't used.")
        # Simple Auth (Plaintext)
        if authtype == 0x1:
            print(
                Fore.GREEN + Style.BRIGHT + "[!] Simple OSPF Authentication " + Fore.YELLOW + Style.BRIGHT + "is used")
            raw = ospfpacket[0][OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(Fore.GREEN + Style.BRIGHT + "[!] Plaintext Password: " + Fore.YELLOW + Style.BRIGHT + string)
        # Crypt Auth (MD5)
        if authtype == 0x02:
            print(
                Fore.GREEN + Style.BRIGHT + "[!] MD5 Auth " + Fore.YELLOW + Style.BRIGHT + "is detected. " + Fore.RED + Style.BRIGHT + "Bruteforce it.")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Ettercap, John the Ripper")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID is: " + Fore.YELLOW + Style.BRIGHT + str(ospfkeyid))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt data length: " + Fore.YELLOW + Style.BRIGHT + str(
                authdatalength))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.YELLOW + Style.BRIGHT + str(
                authseq))
        if args.resolve_mac:
            mac_from_ospf_capture = ospfpacket[0].src
            macinfo = resolve_mac_address(mac_from_ospf_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            return 0


# EIGRP Scanning
def detect_eigrp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the EIGRP protocol...")
    eigrppacket = sniff(filter="ip dst 224.0.0.10", count=1, timeout=args.timeout, iface=args.interface)
    if not eigrppacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. EIGRP isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected EIGRP")
        asnumber = eigrppacket[0][EIGRP].asn
        eigrpneighborip = eigrppacket[0][IP].src
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Here is a little information about the autonomous system")
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " Network Intelligence, MITM, DoS, Blackhole.")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP AS Number: " + Fore.YELLOW + Style.BRIGHT + str(asnumber))
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor: " + Fore.YELLOW + Style.BRIGHT + str(eigrpneighborip))
        if eigrppacket[0].haslayer("EIGRPAuthData"):
            print(Fore.RED + Style.BRIGHT + "[!] There is EIGRP Authentication")
            if eigrppacket[0]["EIGRP Authentication Data"].authtype == 2:
                print(
                    Fore.RED + Style.BRIGHT + "[!] There is EIGRP MD5 Authentication. You can crack this with eigrp2john.py")
                eigrpauthkeyid = eigrppacket[0]["EIGRP Authentication Data"].keyid
                print(
                    Fore.WHITE + Style.BRIGHT + "[*] EIGRP Authentication Key ID: " + Fore.YELLOW + Style.BRIGHT + str(
                        eigrpauthkeyid))
            else:
                print("There's no EIGRP Auth")
        if args.resolve_mac:
            mac_from_eigrp_capture = eigrppacket[0].src
            macinfo = resolve_mac_address(mac_from_eigrp_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            return 0


# VRRP Scanning

def detect_vrrp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the VRRP protocol...")
    vrrppacket = pyshark.LiveCapture(interface=args.interface, bpf_filter="ip host 224.0.0.18")
    vrrppacket.sniff(timeout=args.timeout, packet_count=1)
    if not vrrppacket:
        print(Fore.RED + Style.BRIGHT + "[!] Error. VRRP isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected VRRP")
        vrrppriority = int(vrrppacket[0].vrrp.prio)
        vrrpauthtype = vrrppacket[0].vrrp.auth_type
        ipsrcpacket = vrrppacket[0].ip.src
        vrrpmacsender = vrrppacket[0].eth.src
        vrrp_group_id = vrrppacket[0].vrrp.virt_rtr_id
        vrrp_virt_ip = vrrppacket[0].vrrp.ip_addr
        if vrrppriority <= 255:
            print(
                Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected vulnerable VRRP Value. Even the priority of 255 does not save.")
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MITM, DoS, Blackhole")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Scapy, Loki")
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Group Number (VRID): " + Fore.YELLOW + Style.BRIGHT + str(
                vrrp_group_id))
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Virtual IP Address: " + Fore.YELLOW + Style.BRIGHT + str(
                vrrp_virt_ip))
        else:
            print(Fore.RED + Style.BRIGHT + "[!] VRRP is not vulnerable.")
        if vrrpauthtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP Authentication is not used")
        if vrrpauthtype == 1:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Plaintext VRRP Authentication is used")
            vrrp_plaintext_string = vrrppacket[0].vrrp.auth_string
            print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP Plaintext Key: " + vrrp_plaintext_string)
        if vrrpauthtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[!] VRRP MD5 Auth is used")


    print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Sender IP: " + Fore.YELLOW + Style.BRIGHT + ipsrcpacket)
    print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Sender MAC: " + Fore.YELLOW + Style.BRIGHT + vrrpmacsender)
    if args.resolve_mac:
        mac_from_vrrp_capture = vrrppacket[0].eth.src
        macinfo = resolve_mac_address(mac_from_vrrp_capture)
        print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
        return 0


# STP Scanning
def detect_stp():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the STP protocol...")
    stp_frame = pyshark.LiveCapture(interface=args.interface, bpf_filter="ether host 01:80:c2:00:00:00")
    stp_frame.sniff(timeout=args.timeout, packet_count=1)
    if not stp_frame:
        print(Fore.RED + Style.BRIGHT + "[!] Error. STP isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected STP")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " Partial MITM, DoS")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Yersinia, Grit by Caster")
        stp_vlan_id = stp_frame[0].stp.bridge_ext
        stp_root_prio = stp_frame[0].stp.root_prio
        stp_root_cost = stp_frame[0].stp.root_cost
        print(Fore.GREEN + Style.BRIGHT + "[*] VLAN ID: " + Fore.YELLOW + Style.BRIGHT + str(stp_vlan_id))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Priority: " + Fore.YELLOW + Style.BRIGHT + str(stp_root_prio))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.YELLOW + Style.BRIGHT + str(stp_root_cost))
        if args.resolve_mac:
            mac_from_stp_capture = stp_frame[0].eth.src
            macinfo = resolve_mac_address(mac_from_stp_capture)
            print(Fore.WHITE + Style.BRIGHT + "[!] Vendor: " + macinfo)
            return 0


# LLMNR Scanning
def detect_llmnr():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the LLMNR protocol...")
    llmnr_packet = sniff(filter="ip dst 224.0.0.252", count=1,
                         timeout=args.timeout, iface=args.interface)
    if not llmnr_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. LLMNR isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected LLMNR")
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " LLMNR Spoofing, NetNTLMv2-SSP hashes intercept")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Inveigh, Responder, Metasploit")
        llmnr_sender_mac = llmnr_packet[0][Ether].src
        llmnr_sender_ip = llmnr_packet[0][IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender IP: " + Fore.YELLOW + Style.BRIGHT + str(llmnr_sender_ip))
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender MAC: " + Fore.YELLOW + Style.BRIGHT + str(llmnr_sender_mac))


def detect_mdns():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the MDNS protocol...")
    mdns_packet = pyshark.LiveCapture(interface=args.interface, bpf_filter="ip host 224.0.0.251")
    mdns_packet.sniff(timeout=args.timeout, packet_count=1)
    if not mdns_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. MDNS isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected MDNS")
        mdns_qry_name = mdns_packet[0].mdns.dns_qry_name
        mdns_sender_mac = mdns_packet[0].eth.src
        mdns_sender_address = mdns_packet[0].ip.src
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " MDNS Spoofing, NetNTLMv2-SSP hashes intercept")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Responder")
        print(Fore.GREEN + Style.BRIGHT + "[*] Captured MDNS Query Name: " + Fore.YELLOW + Style.BRIGHT + mdns_qry_name)
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender MAC: " + Fore.YELLOW + Style.BRIGHT + mdns_sender_mac)
        print(
            Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender IP Address: " + Fore.YELLOW + Style.BRIGHT + mdns_sender_address)


# NBT-NS Scanning
def detect_nbns():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the NBNS protocol...")
    nbns_packet = sniff(filter="udp and port 137", count=1,
                        timeout=args.timeout, iface=args.interface)
    if not nbns_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. NBNS isn't detected.")
        return 0
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected NBNS")
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " NBNS Spoofing, NetNTLMv2-SSP hashes intercept")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " Responder, Metasploit")
        nbns_sender_mac = nbns_packet[0][Ether].src
        nbns_sender_ip = nbns_packet[0][IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender IP: " + Fore.YELLOW + Style.BRIGHT + str(nbns_sender_ip))
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender MAC: " + Fore.YELLOW + Style.BRIGHT + str(nbns_sender_mac))


# DHCPv6 DST Addr Filter
def dhcpv6_sniff(pkt):
    dhcpv6_dst_addr = "ff02::1:2"
    if IPv6 in pkt:
        pkt[0][IPv6].dst == dhcpv6_dst_addr
        return True


# DHCPv6 Scanning
def detect_dhcpv6():
    print(Fore.WHITE + Style.BRIGHT + "\n[+] Sniffing the DHCPv6 protocol...")
    dhcpv6_packet = sniff(count=1, lfilter=dhcpv6_sniff,
                          iface=args.interface, timeout=args.timeout)
    if not dhcpv6_packet:
        print(Fore.RED + Style.BRIGHT + "[!] Error. DHCPv6 isn't detected.")
    else:
        print(Fore.GREEN + Style.BRIGHT + "[*] Info:" + Fore.YELLOW + Style.BRIGHT + " Detected DHCPv6")
        print(
            Fore.GREEN + Style.BRIGHT + "[*] Impact:" + Fore.YELLOW + Style.BRIGHT + " DNS Spoofing over IPv4 network")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools:" + Fore.YELLOW + Style.BRIGHT + " mitm6")
        dhcpv6_mac_address_sender = dhcpv6_packet[0][Ether].src
        dhcpv6_packet_sender = dhcpv6_packet[0][IPv6].src
        print(
            Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Request Sender IP: " + Fore.YELLOW + Style.BRIGHT + dhcpv6_packet_sender)
        print(
            Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Request Sender MAC: " + Fore.YELLOW + Style.BRIGHT + dhcpv6_mac_address_sender)
        return 0


def switch_to_promisc(interface):
    print(
        Fore.YELLOW + Style.BRIGHT + "\n[!] Switching " + Fore.BLUE + Style.BRIGHT + interface + Fore.YELLOW + Style.BRIGHT + " to promiscious mode")
    subprocess.call(["ip", "link", "set", interface, "promisc", "on"])
    ip_a_result = subprocess.check_output(["ip", "add", "show", interface])
    promisc_mode_search = re.search(r"PROMISC", ip_a_result.decode())
    if promisc_mode_search:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Switched successfully")
    else:
        print(Fore.RED + Style.BRIGHT + "[!] Error. Not switched to promisc.")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", dest="interface",
                        type=str, required=True, help="Specify your interface")
    parser.add_argument("--timeout", dest="timeout", type=int,
                        required=True, help="Specify the timeout. How much time to sniff")
    parser.add_argument("--resolve-mac", action="store_true", dest="resolve_mac", help="Resolve hardware MAC or not")
    parser.add_argument("--promisc-linux", action="store_true", dest="promisc_linux",
                        help="Enable promisc mode for interface")
    parser.add_argument("--cdp", dest="cdp",
                        action='store_true', help="CDP Scan")
    parser.add_argument("--dtp", dest="dtp",
                        action='store_true', help="DTP Scan")
    parser.add_argument("--mndp", dest="mndp", action='store_true', help="MNDP Scan")
    parser.add_argument("--macsec", dest="macsec", action='store_true', help="MACSec Scan")
    parser.add_argument("--pvst", dest="pvst", action='store_true', help="PVST Scan")
    parser.add_argument("--lldp", dest="lldp", action='store_true', help="LLDP Scan")
    parser.add_argument("--ospf", dest="ospf",
                        action='store_true', help="OSPF Scan")
    parser.add_argument("--eigrp", dest="eigrp",
                        action='store_true', help="EIGRP Scan")
    parser.add_argument("--esrp", dest="esrp",
                        action='store_true', help="ESRP Scan")
    parser.add_argument("--edp", dest="edp",
                        action='store_true', help="EDP Scan")
    parser.add_argument("--vrrp", dest="vrrp",
                        action='store_true', help="VRRP Scan")
    parser.add_argument("--hsrp", dest="hsrp",
                        action='store_true', help="HSRP Scan")
    parser.add_argument("--stp", dest="stp",
                        action='store_true', help="STP Scan")
    parser.add_argument("--glbp", dest="glbp",
                        action='store_true', help="GLBP Scan")
    parser.add_argument("--llmnr", dest="llmnr",
                        action='store_true', help="LLMNR Scan")
    parser.add_argument("--nbns", dest="nbns",
                        action='store_true', help="NBNS Scan")
    parser.add_argument("--mdns", dest="mdns",
                        action='store_true', help="mDNS Scan")
    parser.add_argument("--dhcpv6", dest="dhcpv6",
                        action='store_true', help="DHCPv6 Scan")
    parser.add_argument("--fullscan", dest="fullscan",
                        action='store_true', help="Scan all protocols")

    args = parser.parse_args()

    if args.cdp or args.fullscan:
        detect_cdp()

    if args.dtp or args.fullscan:
        detect_dtp()

    if args.lldp or args.fullscan:
        detect_lldp()

    if args.macsec or args.fullscan:
        detect_macsec()

    if args.mndp or args.fullscan:
        detect_mndp()

    if args.ospf or args.fullscan:
        detect_ospf()

    if args.eigrp or args.fullscan:
        detect_eigrp()

    if args.edp or args.fullscan:
        detect_edp()

    if args.esrp or args.fullscan:
        detect_esrp()

    if args.vrrp or args.fullscan:
        detect_vrrp()

    if args.hsrp or args.fullscan:
        detect_hsrp()

    if args.glbp or args.fullscan:
        detect_glbp()

    if args.stp or args.fullscan:
        detect_stp()

    if args.pvst or args.fullscan:
        detect_pvst()

    if args.llmnr or args.fullscan:
        detect_llmnr()

    if args.nbns or args.fullscan:
        detect_nbns()

    if args.mdns or args.fullscan:
        detect_mdns()

    if args.dhcpv6 or args.fullscan:
        detect_dhcpv6()
