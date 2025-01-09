# IPv6 Enumerator
Host discovery in IPv6 networks.


### Usage:
```
sudo python scanner.py [-h] [-l] [-w WAIT] [-p] [-n] [-a] [--group-all-nodes] [--group-routers] [--group-dhcp] [--group-mldv2] [--group-relay] [--all-groups] [-s] [-k] [--subnet-size SUBNET_SIZE] [interface]

IPv6 network scanner

positional arguments:
  interface             Network interface to scan

options:
  -h, --help            show this help message and exit
  -l, --list            List active network interfaces
  -w WAIT, --wait WAIT  Time to wait for responses after each multicast probe (default: 0.5s)

  -p, --ping            Enable ICMPv6 Multicast Groups Echo Request discovery
  -n, --ns              Enable ICMPv6 Multicast Groups Neighbor Solicitation discovery

  -a, --all             Enable all scanning methods and groups

  --group-all-nodes     Probe all nodes = ALL group = ff02::1
  --group-routers       Probe all routers = RTR group = ff02::2
  --group-dhcp          Probe all DHCP servers = DHCP group = ff02::1:2
  --group-mldv2         Probe all MLDv2-capable routers = MLDv2 group = ff02::16
  --group-relay         Probe all DHCP relays = RELAY group = ff02::1:3

  --all-groups          Probe all multicast groups

  -s, --solicit         Include solicited-node multicast scanning
  -k, --network         Scan networks of discovered hosts (default: /125 = 8 addresses)
  --subnet-size SUBNET_SIZE
                        Subnet size is the prefix length for network scanning (example: 120 for /120 = 256 addresses). 
                        Smaller number = larger network = longer scan time. Default: 125 for /125 = 8 addresses
```

### Install:
```bash
# optional:
git clone https://github.com/dmatscheko/ipv6_enumerator.git
cd ipv6_enumerator
python -m venv venv
source venv/bin/activate
# necessary:
pip install netifaces scapy ipaddress
```
