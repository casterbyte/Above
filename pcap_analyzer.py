from scapy.all import *
from scapy.layers.l2 import *
from scapy.contrib.ospf import *
from scapy.contrib.cdp import *
from scapy.contrib.eigrp import *
from scapy.contrib.dtp import *
from scapy.layers.ipsec import *
from scapy.layers.vrrp import *
from scapy.layers.hsrp import *
from scapy.layers.llmnr import *
from colorama import Fore, Style

# This is a special module for Above to offline check .pcap dumps

# for decode ospf simple auth password
def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value

def extract_protocols(pcap_file):
    ospf_packets = []
    hsrp_packets = []
    eigrp_packets = []
    stp_packets = []
    cdp_packets = []
    dtp_packets = []
    vrrp_packets = []
    llmnr_packets = []
    nbt_ns_packets = []
    mdns_packets = []
    dhcpv6_packets = []

    packets = rdpcap(pcap_file)

    for packet in packets:
        if OSPF_Hdr in packet: # OSPF
            ospf_packets.append(packet)
        if HSRP in packet and packet[HSRP].state == 16 and packet[HSRP].priority < 255: # HSRP
            hsrp_packets.append(packet)
        if EIGRP in packet: # EIGRP
            eigrp_packets.append(packet)
        if STP in packet: # STP
            stp_packets.append(packet)
        if "Cisco Discovery Protocol version 2" in packet: # CDP
            cdp_packets.append(packet)
        if DTP in packet: # DTP
            dtp_packets.append(packet)
        if VRRP in packet: # VRRP
            vrrp_packets.append(packet)
        if AH in packet: # Authentication Header (for VRRP auth)
            vrrp_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '224.0.0.252' and packet[UDP].dport == 5355: # LLMNR
            llmnr_packets.append(packet)
        if Ether in packet and UDP in packet and packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and packet[UDP].dport == 137: # NBT-NS
            nbt_ns_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '224.0.0.251' and packet[UDP].dport == 5353: # MDNS
            mdns_packets.append(packet)
        if UDP in packet and (packet[UDP].dport == 546 or packet[UDP].dport == 547): #DHCPv6
            dhcpv6_packets.append(packet)

    return (ospf_packets, hsrp_packets, eigrp_packets, stp_packets,
            cdp_packets, dtp_packets, vrrp_packets, llmnr_packets,
            nbt_ns_packets, mdns_packets, dhcpv6_packets)

def analyze_pcap(pcap_file):
    ospf, hsrp, eigrp, stp, cdp, dtp, vrrp, llmnr, nbt_ns, mdns, dhcpv6 = extract_protocols(pcap_file)

    if cdp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected CDP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering, DoS")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Wireshark")
        cdphostname = cdp[0][CDPMsgDeviceID].val
        print(
            Fore.GREEN + Style.BRIGHT + "[*] System Hostname: " + Fore.WHITE + Style.BRIGHT + str(cdphostname.decode()))
        cdphardwareversion = cdp[0][CDPMsgSoftwareVersion].val
        print(Fore.GREEN + Style.BRIGHT + "[*] Target Version: " + Fore.WHITE + Style.BRIGHT + str(
            cdphardwareversion.decode()))
        cdphardwareplatform = cdp[0][CDPMsgPlatform].val
        print(Fore.GREEN + Style.BRIGHT + "[*] Target Platform: " + Fore.WHITE + Style.BRIGHT + str(
            cdphardwareplatform.decode()))
        cdpportid = cdp[0][CDPMsgPortID].iface
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + str(cdpportid.decode()))
        if cdp[0].haslayer(CDPAddrRecordIPv4):
            cdpaddr = cdp[0][CDPAddrRecordIPv4].addr
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + cdpaddr)

    if dtp:
       print(Fore.WHITE + Style.BRIGHT + '-' * 50)
       print(Fore.WHITE + Style.BRIGHT + "[+] Detected DTP Protocol")
       print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "VLAN Segmentation Bypass")
       print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
       dtp_neighbor_mac = dtp[0][DTPNeighbor].neighbor
       print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(dtp_neighbor_mac))


    if ospf:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected OSPF Protocol")
        areaID = ospf[0][OSPF_Hdr].area
        authtype = ospf[0][OSPF_Hdr].authtype
        ospfkeyid = ospf[0][OSPF_Hdr].keyid
        authdatalength = ospf[0][OSPF_Hdr].authdatalen
        authseq = ospf[0][OSPF_Hdr].seq
        hellosource = ospf[0][OSPF_Hdr].src
        print(Fore.GREEN + Style.BRIGHT + "[+] Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Area ID: " + Fore.WHITE + Style.BRIGHT + str(areaID))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor: " + Fore.WHITE + Style.BRIGHT + str(hellosource))
        # No Auth
        if authtype == 0x0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        # Simple Auth (cleartext string)
        if authtype == 0x1:
            raw = ospf[0][OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(
                Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.YELLOW + Style.BRIGHT + "Plaintext Phrase: " + string)
        # Crypt Auth (MD5)
        if authtype == 0x02:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: Ettercap, John the Ripper")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.WHITE + Style.BRIGHT + str(ospfkeyid))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Data Length: " + Fore.WHITE + Style.BRIGHT + str(authdatalength))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.WHITE + Style.BRIGHT + str(authseq))

    if hsrp:
       print(Fore.WHITE + Style.BRIGHT + '-' * 50)
       print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRP Protocol")
       hsrpv1senderip = hsrp[0][IP].src
       hsrpv1sendermac = hsrp[0][Ether].src
       hsrpv1group = hsrp[0][HSRP].group
       hsrpv1vip = hsrp[0][HSRP].virtualIP
       print(Fore.YELLOW + Style.BRIGHT + "[*] HSRP ACTIVE Vulnerable Priority Value: " + Fore.WHITE + Style.BRIGHT + str((hsrp[0].priority)))
       print(Fore.GREEN + Style.BRIGHT + "[+] Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
       print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, Yersinia")
       print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(hsrpv1group))
       print(Fore.GREEN + Style.BRIGHT + "[+] HSRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(hsrpv1vip))
       print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + hsrpv1senderip)
       print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + hsrpv1sendermac)
       if hsrp[0].haslayer(HSRPmd5):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
       else:
            if hsrp[0][HSRP].auth:
                hsrpv1_plaintext = hsrp[0][HSRP].auth
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext Phrase: " + simplehsrppass)

    if vrrp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRP Protocol")
        if vrrp[0].haslayer(AH):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "AH")
            print(Fore.YELLOW + Style.BRIGHT + "[*] If this router is running RouterOS and AH is active - at this time, bruteforcing AH hashes from RouterOS is considered impossible")
            print(Fore.YELLOW + Style.BRIGHT + "[*] If it is keepalived, there is no problem with bruteforcing the AH hash")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Unfortunately at the moment there is no tool that sends VRRP packets with AH authentication support")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Skipping...")
            return 0
        vrrppriority = vrrp[0][VRRP].priority
        vrrpgroup = vrrp[0][VRRP].vrid
        vrrpauthtype = vrrp[0][VRRP].authtype
        ipsrcpacket = vrrp[0][IP].src
        vrrpmacsender = vrrp[0][Ether].src
        vrrpvip = vrrp[0][VRRP].addrlist
        # The problem is that usually the configuration does not allow you to set the priority to 255 on the hardware, only 254.
        if vrrppriority <= 255:
            print(
                Fore.YELLOW + Style.BRIGHT + "[*] VRRP Master Vulnerable Priority Value: " + Fore.WHITE + Style.BRIGHT + str(
                    vrrppriority))
            print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        # VRRP Null Auth    
        if vrrpauthtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        # VRRP Plaintext Auth    
        if vrrpauthtype == 0x1:
            print(
                Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext. Look at the password in Wireshark")
        # VRRP Cryptographic Auth    
        if vrrpauthtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(vrrpvip))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(vrrpgroup))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + ipsrcpacket)
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + vrrpmacsender)       
    

    if eigrp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EIGRP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        asnumber = eigrp[0][EIGRP].asn
        eigrpneighborip = eigrp[0][IP].src
        if eigrp[0].haslayer("EIGRPAuthData"):
            print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
            if eigrp[0]["EIGRP"]["EIGRP Authentication Data"].authtype == 2:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
                print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: eigrp2john.py, John the Ripper")
        else:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        print(Fore.GREEN + Style.BRIGHT + "[*] AS Number: " + Fore.WHITE + Style.BRIGHT + str(asnumber))
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor: " + Fore.WHITE + Style.BRIGHT + str(eigrpneighborip))


    if stp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected STP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "Partial MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        stp_root_mac = stp[0][STP].rootmac
        stp_root_id = stp[0][STP].rootid
        stp_root_pathcost = stp[0][STP].pathcost
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root MAC: " + Fore.WHITE + Style.BRIGHT + str(stp_root_mac))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root ID: " + Fore.WHITE + Style.BRIGHT + str(stp_root_id))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.WHITE + Style.BRIGHT + str(stp_root_pathcost))

    if llmnr:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLMNR Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "LLMNR Spoofing, Credentials interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        llmnr_sender_mac = llmnr[0][Ether].src
        llmnr_sender_ip = llmnr[0][IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender IP: " + Fore.WHITE + Style.BRIGHT + str(llmnr_sender_ip))
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Sender MAC: " + Fore.WHITE + Style.BRIGHT + str(llmnr_sender_mac))

    if nbt_ns:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected NBT-NS Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "NBT-NS Spoofing, Credentials interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        nbns_packet_mac = nbt_ns[0][Ether].src
        nbns_packet_ip = nbt_ns[0][IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender IP: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet_ip))
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Sender MAC: " + Fore.WHITE + Style.BRIGHT + str(nbns_packet_mac))

    if mdns:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MDNS Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "MDNS Spoofing, Credentials interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        mdns_packet_mac = mdns[0][Ether].src
        mdns_packet_ip = mdns[0][IP].src
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender IP: " + Fore.WHITE + Style.BRIGHT + str(mdns_packet_ip))
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Sender MAC: " + Fore.WHITE + Style.BRIGHT + str(mdns_packet_mac))

    if dhcpv6:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCPv6 Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Impact: " + Fore.YELLOW + Style.BRIGHT + "DNS IPv6 Spoofing")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "mitm6")
        dhcpv6_mac_address_sender = dhcpv6[0][Ether].src
        dhcpv6_packet_sender = dhcpv6[0][IPv6].src
        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Sender IP: " + Fore.WHITE + Style.BRIGHT + dhcpv6_packet_sender)
        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Sender MAC: " + Fore.WHITE + Style.BRIGHT + dhcpv6_mac_address_sender)       



if __name__ == "__main__":
    analyze_pcap()
