# IPv6 Enumerator
An IPv6 network scanner.

```
usage: scanner.py [-h] [-l] [-w WAIT] [-s] [-n] [--max-prefix MAX_PREFIX] [interface]

IPv6 network scanner

positional arguments:
  interface             Network interface to scan

options:
  -h, --help            show this help message and exit
  -l, --list            List active network interfaces
  -w WAIT, --wait WAIT  Time to wait for responses after each multicast probe (default: 0.5s)
  -s, --solicit         Include solicited-node multicast scanning
  -n, --network         Scan networks of discovered hosts (default: /125 = 8 addresses)
  --max-prefix MAX_PREFIX
                        Maximum prefix length for network scanning (example: 120 for /120 = 256 addresses). 
                        Smaller number = larger network = longer scan time. Default: 125 for /125 = 8 addresses
```
