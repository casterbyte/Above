from scapy.all import rdpcap, Ether, IP, HSRP, HSRPmd5, VRRP, VRRPv3, STP, IPv6, AH, UDP, LLMNRQuery, Dot3
from scapy.contrib.macsec import MACsec, MACsecSCI
from scapy.contrib.eigrp import EIGRP
from scapy.contrib.ospf import OSPF_Hdr
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4
from scapy.contrib.lldp import LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID, LLDPDUManagementAddress, LLDPDU
from scapy.contrib.dtp import DTP # Connecting only the necessary Scapy components
import socket
from colorama import Fore, Style

# This is a module for Above to offline check traffic dumps (.pcap)

def extract_protocols(pcap_file):
    ospf_packets = []
    dtp_packets = []
    hsrp_packets = []
    eigrp_packets = []
    stp_packets = []
    lldp_packets = []
    cdp_packets = []
    vrrp_packets = []
    llmnr_packets = []
    nbt_ns_packets = []
    mdns_packets = []
    dhcpv6_packets = []
    ssdp_packets = []
    mndp_packets = []
    glbp_packets = []
    macsec_packets = []
    packets = rdpcap(pcap_file)

    for packet in packets:
        if MACsec in packet:
            macsec_packets.append(packet)
        if LLDPDU in packet: # LLDP Detection
            lldp_packets.append(packet)
        if OSPF_Hdr in packet: # OSPF Detection
            ospf_packets.append(packet)
        if HSRP in packet and packet[HSRP].state == 16 and packet[HSRP].priority < 255: # HSRP Detection
            hsrp_packets.append(packet)
        if EIGRP in packet: # EIGRP Detection
            eigrp_packets.append(packet)
        if STP in packet: # STP Detection
            stp_packets.append(packet)
        if CDPv2_HDR in packet: # CDP Detection
            cdp_packets.append(packet)
        if DTP in packet: # DTP Detection
            dtp_packets.append(packet)
        if VRRP in packet: # VRRPv2 Detection
            vrrp_packets.append(packet)
        if AH in packet: # Authentication Header (only for VRRP) VRRP with AH is configured in RouterOS or keepalived
            vrrp_packets.append(packet)
        if VRRPv3 in packet: # VRRPv3 Detection
            vrrp_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '224.0.0.252' and packet[UDP].dport == 5355: # LLMNR Detection
            llmnr_packets.append(packet)
        if Ether in packet and UDP in packet and packet[Ether].dst == 'ff:ff:ff:ff:ff:ff' and packet[UDP].dport == 137: # NBT-NS Detection
            nbt_ns_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '224.0.0.251' and packet[UDP].dport == 5353: # MDNS Detection
            mdns_packets.append(packet)
        if UDP in packet and (packet[UDP].dport == 546 or packet[UDP].dport == 547): #DHCPv6 Detection
            dhcpv6_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '239.255.255.250' and packet[UDP].dport == 1900: # SSDP Detection
            ssdp_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '255.255.255.255' and packet[UDP].dport == 5678: # MNDP Detection
            mndp_packets.append(packet)
        if IP in packet and UDP in packet and packet[IP].dst == '224.0.0.102' and packet[UDP].dport == 3222: # GLBP Detection
            glbp_packets.append(packet)

    return (ospf_packets, hsrp_packets, eigrp_packets, stp_packets, cdp_packets, dtp_packets, vrrp_packets, llmnr_packets,
            lldp_packets, nbt_ns_packets, mdns_packets, dhcpv6_packets, ssdp_packets, mndp_packets, glbp_packets, macsec_packets)

def analyze_pcap(pcap_file):
    ospf, hsrp, eigrp, stp, cdp, dtp, vrrp, llmnr, lldp, nbt_ns, mdns, dhcpv6, ssdp, mndp, glbp, macsec = extract_protocols(pcap_file)

    if macsec:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MACSec")
        print(Fore.YELLOW + Style.BRIGHT + "[+] The network may be using 802.1X, keep that in mind")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] System Identifier: " + Fore.WHITE + Style.BRIGHT + macsec[0][MACsec][MACsecSCI].system_identifier)
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] System Identifier: " + Fore.WHITE + Style.BRIGHT + "Not Found")
    if cdp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected CDP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering, DoS (CDP Flood)")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Above, Wireshark, Yersinia")
        print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + str(cdp[0][CDPMsgDeviceID].val.decode()))
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + str(cdp[0][CDPMsgSoftwareVersion].val.decode()))
        print(Fore.GREEN + Style.BRIGHT + "[*] Platform: " + Fore.WHITE + Style.BRIGHT + str(cdp[0][CDPMsgPlatform].val.decode()))
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + str(cdp[0][CDPMsgPortID].iface.decode()))
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + str(cdp[0][CDPAddrRecordIPv4].addr))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable CDP on endpoint ports. Do not disrupt the IP phones, be careful")    

    if dtp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DTP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "VLAN Segmentation Bypass")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(dtp[0][Dot3].src))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable DTP on the switch ports")    

    if lldp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLDP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Above, Wireshark")
        try:
            print (Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + str(lldp[0][LLDPDUSystemName].system_name.decode()))
        except:
            print (Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            print (Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + str(lldp[0][LLDPDUSystemDescription].description.decode()))
        except:
            print (Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            print (Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + str(lldp[0][LLDPDUPortID].id.decode()))
        except:
            print (Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            lldp_mgmt_address_bytes = lldp[0][LLDPDUManagementAddress].management_address # capture mgmt address on the variable
            decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes) # decode ip address
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + decoded_mgmt_address)
        except:
            print (Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        # Mitigation    
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLDP on endpoint ports. Do not disrupt the IP phones, be careful")
        
    if ospf:
        def hex_to_string(hex):
            if hex[:2] == '0x':
                hex = hex[2:]
            string_value = bytes.fromhex(hex).decode('utf-8')
            return string_value
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected OSPF Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Area ID: " + Fore.WHITE + Style.BRIGHT + str(ospf[0][OSPF_Hdr].area))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(ospf[0][OSPF_Hdr].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(ospf[0][Ether].src))
    # No Auth
        if ospf[0][OSPF_Hdr].authtype == 0x0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
    # Plaintext Auth
        if ospf[0][OSPF_Hdr].authtype == 0x1:
            raw = ospf[0][OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.YELLOW + Style.BRIGHT + "Plaintext Phrase: " + string)
    # Crypt Auth (MD5)
        if ospf[0][OSPF_Hdr].authtype == 0x02:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: Ettercap, John the Ripper")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.WHITE + Style.BRIGHT + str(ospf[0][OSPF_Hdr].keyid))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Data Length: " + Fore.WHITE + Style.BRIGHT + str(authdatalength = ospf[0][OSPF_Hdr].authdatalen))
            print(Fore.GREEN + Style.BRIGHT + "[*] Crypt Auth Sequence Number: " + Fore.WHITE + Style.BRIGHT + str(ospf[0][OSPF_Hdr].seq))
        # Mitigation    
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use cryptographic authentication, filter OSPF traffic with ACLs")

    if hsrp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP active router priority: " + Fore.WHITE + Style.BRIGHT + str((hsrp[0].priority)))
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, Yersinia")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(hsrp[0][HSRP].group))
        print(Fore.GREEN + Style.BRIGHT + "[+] HSRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(hsrp[0][HSRP].virtualIP))
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(hsrp[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(hsrp[0][Ether].src))
        if hsrp[0].haslayer(HSRPmd5):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
        else:
            if hsrp[0][HSRP].auth:
                hsrpv1_plaintext = hsrp[0][HSRP].auth # capture password on the variable
                simplehsrppass = hsrpv1_plaintext.decode("UTF-8") # decoding to utf-8
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext Phrase: " + simplehsrppass)
            # Mitigation        
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use cryptographic authentication, filtering HSRP traffic with ACLs")
       
    if vrrp:
        # Detect AH Authentication
        if vrrp[0].haslayer(AH):
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Protocol") 
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "AH")
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][Ether].src))
            print(Fore.YELLOW + Style.BRIGHT + "[*] If this router is running RouterOS and AH is active - at this time, bruteforcing AH hashes from RouterOS is considered impossible")
            print(Fore.YELLOW + Style.BRIGHT + "[*] If it is keepalived, there is no problem with bruteforcing the AH hash")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Unfortunately at the moment there is no tool that sends VRRP packets with AH authentication support")
            return 0
        # VRRPv3 Detection
        if vrrp[0].haslayer(VRRPv3):
            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv3 Protocol")
            if vrrp[0][VRRPv3].priority <= 255: # The problem is that usually the configuration does not allow you to set the priority to 255 on the hardware, only 254.
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 master router priority: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRPv3].priority))
                print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Group Number: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRPv3].vrid))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][IP].src))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][Ether].src))
                print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRPv3].addrlist))
                print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter VRRP traffic using ACLs/FW")
                return 0
        # VRRPv2 Detection    
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Protocol")
        if vrrp[0][VRRP].priority <= 255: # The problem is that usually the configuration does not allow you to set the priority to 255 on the hardware, only 254.
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 master router priority: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRP].priority))
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        # VRRP Null Auth    
        if vrrp[0][VRRP].authtype == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        # VRRP Plaintext Auth    
        if vrrp[0][VRRP].authtype == 0x1:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext. Look at the password in Wireshark")
        # VRRP Cryptographic Auth    
        if vrrp[0][VRRP].authtype == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Group Number: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRP].vrid))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][Ether].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(vrrp[0][VRRP].addrlist))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use cryptographic authentication, filter VRRP traffic using ACLs")            

    if eigrp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EIGRP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        if eigrp[0].haslayer("EIGRPAuthData"):
            print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
            if eigrp[0]["EIGRP"]["EIGRP Authentication Data"].authtype == 2:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools for bruteforce: " + Fore.WHITE + Style.BRIGHT + "eigrp2john.py, John the Ripper")
        else:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "No")
        print(Fore.GREEN + Style.BRIGHT + "[*] AS Number: " + Fore.WHITE + Style.BRIGHT + str(eigrp[0][EIGRP].asn))
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(eigrp[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + str(eigrp[0][Ether].src))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use cryptographic authentication, filter EIGRP traffic with ACLs")

        
    if stp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected STP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Partial MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Switch MAC: " + Fore.WHITE + Style.BRIGHT + str(stp[0][STP].rootmac))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root ID: " + Fore.WHITE + Style.BRIGHT + str(stp[0][STP].rootid))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.WHITE + Style.BRIGHT + str(stp[0][STP].pathcost))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable BPDU Guard")

    if llmnr:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLMNR Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "LLMNR Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + str(llmnr[0][LLMNRQuery]["DNS Question Record"].qname.decode()))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(llmnr[0][LLMNRQuery].id))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(llmnr[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(llmnr[0][Ether].src))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLMNR with GPOs")
        

    if nbt_ns:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected NBT-NS Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "NBT-NS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + str(nbt_ns[0]["NBNS registration request"].QUESTION_NAME.decode()))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(nbt_ns[0]["NBNS Header"].NAME_TRN_ID))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(nbt_ns[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(nbt_ns[0][Ether].src))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable NBT-NS with GPOs")

    if mdns:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MDNS Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MDNS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        # There is no Query Name output here because at the time of Above v2.3 - Scapy does not know how to handle MDNS packets
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(mdns[0][IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(mdns[0][Ether].src))
        print(Fore.YELLOW + Style.BRIGHT + "[*] MDNS Spoofing works specifically against Windows machines")
        print(Fore.YELLOW + Style.BRIGHT + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter MDNS traffic using VACL/VMAP. Be careful with MDNS filtering, you can disrupt printers, Chromecast, etc. Monitor attacks on IDS")   

    if dhcpv6:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCPv6 Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "DNS IPv6 Spoofing")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "mitm6")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(dhcpv6[0][IPv6].src))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker IP: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(dhcpv6[0][Ether].src))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + "Not Found")
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable RA Guard, SAVI")

    if ssdp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected SSDP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Credentials Interception, MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "evil-ssdp")
        print(Fore.GREEN + Style.BRIGHT + "[!] The attack may seem too theoretical")
        print(Fore.YELLOW + Style.BRIGHT + "[*] SSDP Spoofing works specifically against Windows machines")
        print(Fore.YELLOW + Style.BRIGHT + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
        print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(ssdp[0][Ether].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(ssdp[0][IP].src))
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter SSDP traffic using VACL/VMAP, monitor attacks on IDS")

    if mndp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MNDP Protocol")
        print(Fore.WHITE + Style.BRIGHT + "[*] MikroTik device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Above, Wireshark")
        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + str(mndp[0][Ether].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(mndp[0][IP].src))
        print(Fore.YELLOW + Style.BRIGHT + "[*] You can get more information from the packet in Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[*] The MNDP protocol is not yet implemented in Scapy")
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable MNDP on endpoint ports")
    
    if glbp:
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected GLBP Protocol")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki")
        print(Fore.YELLOW + Style.BRIGHT + "[!] GLBP has not yet been implemented by Scapy")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Check AVG router priority values manually using Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[!] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.")
        print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Sender MAC: " + Fore.WHITE + Style.BRIGHT + str(glbp[0][Ether].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Sender IP: " + Fore.WHITE + Style.BRIGHT + str(glbp[0][IP].src))
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use cryptographic authentication, filtering GLBP traffic with ACLs. However, given the specifics of the GLBP setting (AVG/AVF).")

if __name__ == "__main__":
    analyze_pcap()
