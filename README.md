# Above

Network Vulnerability Scanner by Caster

```
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

                                                                                          Network Vulnerability Scanner
                                                                                         VERSION: 2.0, CODENAME: JOANNA
                                                                                Author: Caster, @c4s73r, <c4s73r@protonmail.com>
usage: Above.py [-h] --interface INTERFACE --timeout TIMEOUT [--resolve-mac] [--promisc-linux] [--cdp] [--dtp] [--mndp] [--macsec] [--pvst] [--lldp] [--ospf] [--eigrp] [--esrp] [--edp] [--vrrp] [--hsrp]
                [--stp] [--glbp] [--llmnr] [--nbns] [--mdns] [--dhcpv6] [--fullscan]

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Specify your interface
  --timeout TIMEOUT     Specify the timeout. How much time to sniff
  --resolve-mac         Resolve hardware MAC or not
  --promisc-linux       Enable promisc mode for interface (Linux). Root privileges required!
  --cdp                 CDP Scan
  --dtp                 DTP Scan
  --mndp                MNDP Scan
  --macsec              MACSec Scan
  --pvst                PVST+ Scan
  --lldp                LLDP Scan
  --ospf                OSPF Scan
  --eigrp               EIGRP Scan
  --esrp                ESRP Scan
  --edp                 EDP Scan
  --vrrp                VRRP Scan
  --hsrp                HSRP Scan
  --stp                 STP Scan
  --glbp                GLBP Scan
  --llmnr               LLMNR Scan
  --nbns                NBNS Scan
  --mdns                mDNS Scan
  --dhcpv6              DHCPv6 Scan
  --fullscan            Scan all protocols
```

## Mechanics

This script is based on a sniff of network traffic. "Above" is fully autonomous and works in passive mode, creating no noise on the air. Since the 2.0 release, it supports 18 protocols

```
MACSec (802.1AE)
MNDP (Mikrotik Neighbor Discovery Protocol)
DTP (Dynamic Trunking Protocol)
CDP (Cisco Discovery Protocol)
EDP (Extreme Discovery Protocol)
ESRP (Extreme Standby Router Protocol)
LLDP (Link Layer Discovery Protocol)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
VRRP (Virtual Router Redundancy Protocol)
HSRP (Host Standby Redundancy Protocol)
GLBP (Gateway Load Balancing Protocol)
STP (Spanning Tree Protocol)
PVST (Per VLAN Spanning Tree)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCPv6 (Dynamic Host Configuration Protocol v6)
```

The scanner waits for the following arguments as input:

  - Network interface
  - Timeout: The amount of time that a packet will be waiting for, according to the filters inside the scanner
  - Protocol
  - Promisc Mode
  - Resolve MAC: Vendor detection by MAC (requires Internet access, creates a little noise in the form of HTTP requests

Example (OSPF and VRRP protocol scan):

```
sudo python3 Above.py --interface eth0 --timeout 60 --ospf --vrrp --resolve-mac --promisc-mode
```

When the tool finishes analyzing the protocol, it outputs a little information about its configuration, the impact from the attack, which tool the attacker uses

## Install

Above" requires some dependencies to be installed. If necessary, you can use virtualenv

```
sudo pip3 install -r requirements.txt
```

## Code Design Issues

"Above" has problems with the code in terms of design/refactoring. I was putting the emphasis specifically on the workability of the code.

## Last Word

This tool is dedicated to the track "View From Above (Remix)" by KOAN Sound
