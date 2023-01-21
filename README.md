# Above
Sniff-based Network Vulnerability Scanner

```
python3 Above.py --help
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

Sniff-based Network Vulnerability Scanner
Author: Caster, @c4s73r, <c4s73r@protonmail.com>

To skip scanning some protocol during a full scan - hit CTRL + C
usage: Above.py [-h] --interface INTERFACE --timeout TIMEOUT [--cdp] [--dtp] [--lldp] [--ospf] [--eigrp] [--vrrp] [--hsrpv1] [--stp] [--llmnr] [--nbns] [--dhcpv6] [--fullscan]

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Specify your interface
  --timeout TIMEOUT     Specify the timeout. How much time to sniff
  --cdp                 CDP Scan
  --dtp                 DTP Scan
  --lldp                LLDP Scan
  --ospf                OSPF Scan
  --eigrp               EIGRP Scan
  --vrrp                VRRP Scan
  --hsrpv1              HSRPv1 Scan
  --stp                 STP Scan
  --llmnr               LLMNR Scan
  --nbns                NBNS Scan
  --dhcpv6              DHCPv6 Scan
  --fullscan            Scan all protocols
  ```
## Mechanics

This script is based on a sniff of network traffic. At the moment it supports the following protocols:

```
DTP (Dynamic Trunking Protocol)
CDP (Cisco Discovery Protocol)
LLDP (Link Layer Discovery Protocol)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
VRRP (Virtual Router Redundancy Protocol)
HSRP (Host Standby Redundancy Protocol)
STP (Spanning Tree Protocol)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
DHCPv6 (Dynamic Host Configuration Protocol v6)
```
**THE SCANNER DOES NOT CREATE ANY NOISE ON THE NETWORK**

The scanner waits for the following arguments as input:
  - network interface (--interface)
  - timeout (the amount of time that a packet will be waiting for, according to the filters inside the scanner) (--timeout)
  - target protocol (--cdp --dtp --lldp --ospf --eigrp --vrrp --hsrpv1 --stp --llmnr --nbns --dhcpv6 --fullscan)
  
Example (OSPF and VRRP protocol scan):
```
sudo python3 Above.py --interface eth0 --timeout 60 --ospf --vrrp
```
After the scanner finishes sniffing a certain protocol, it will display some information about the protocol itself, the impact of the attack and which tool for the attack can be used. Over time, based on your issues, this parameter will improve.

## Preparing before the sniff
```
sudo pip3 install -r requirements.txt
```



