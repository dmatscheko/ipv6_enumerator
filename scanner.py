#!/usr/bin/env python3
import sys
import socket
import time
import struct
import netifaces
import argparse
import ipaddress
from scapy.all import *
from collections import defaultdict

class IPv6Scanner:
    def __init__(self, interface):
        self.interface = interface
        self.discovered_hosts = {}  # IP to (MAC, set(groups)) mapping
        self.probe_wait = 0.5  # Default wait time between probes
        self.network_scan = False
        self.subnet_size_limit = 120  # Default minimum prefix length (/120 = 256 addresses)
        self.solicit_scan = False
        
        # Set up Scapy settings
        conf.verb = 0
        
        # Try to get interface MAC address
        try:
            if_addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in if_addrs:
                self.if_mac = if_addrs[netifaces.AF_LINK][0]['addr']
            else:
                self.if_mac = "00:00:00:00:00:00"
        except:
            self.if_mac = "00:00:00:00:00:00"
        
        # Multicast groups definition moved to class level for easier access
        self.multicast_groups = {
            'ff02::1': 'ALL',      # All Nodes
            'ff02::2': 'RTR',      # All Routers
            'ff02::1:2': 'DHCP',   # All DHCP Servers
            'ff02::16': 'MLDv2',   # All MLDv2-capable Routers
            'ff02::1:3': 'RELAY'   # All DHCP Relays
        }
        
    @staticmethod
    def list_interfaces():
        """List active network interfaces and their addresses"""
        print("[*] Active network interfaces:")
        active_interfaces = []
        
        for iface in netifaces.interfaces():
            # Skip loopback interfaces
            if iface.startswith('lo') or iface.startswith('localhost'):
                continue
                
            addrs = netifaces.ifaddresses(iface)
            has_addresses = (netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]) or \
                          (netifaces.AF_INET6 in addrs and [a for a in addrs[netifaces.AF_INET6] 
                           if not a['addr'].startswith('fe80:')])
            
            if has_addresses:
                print(f"\nInterface: {iface}")
                active_interfaces.append(iface)
                
                if netifaces.AF_INET in addrs:
                    print("  IPv4 addresses:")
                    for addr in addrs[netifaces.AF_INET]:
                        print(f"    {addr['addr']}")
                
                if netifaces.AF_INET6 in addrs:
                    print("  IPv6 addresses:")
                    for addr in addrs[netifaces.AF_INET6]:
                        if not addr['addr'].startswith('fe80:'):
                            print(f"    {addr['addr']}")
                
                if netifaces.AF_LINK in addrs:
                    print("  MAC address:")
                    print(f"    {addrs[netifaces.AF_LINK][0]['addr']}")
        
        if not active_interfaces:
            print("\nNo active interfaces with IPv4/IPv6 addresses found!")
            
        return active_interfaces
        
    def create_icmp6_socket(self):
        """Create a raw ICMPv6 socket"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("LL", 2, 0))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 
                          socket.if_nametoindex(self.interface))
            return sock
        except Exception as e:
            print(f"[-] Error creating socket: {str(e)}")
            return None

    def extract_mac_from_ipv6(self, ipv6_addr):
        """Extract MAC address from EUI-64 based IPv6 address"""
        try:
            segments = ipv6_addr.split(':')
            if len(segments) != 8:
                return None
                
            eui_segments = segments[4:8]
            
            if eui_segments[0].endswith('ff') and eui_segments[1].startswith('fe'):
                mac_parts = [
                    eui_segments[0][:-2],
                    eui_segments[1][2:],
                    eui_segments[2],
                    eui_segments[3]
                ]
                
                first_byte = int(mac_parts[0], 16)
                first_byte ^= 0b00000010
                mac_parts[0] = f"{first_byte:02x}"
                
                return ':'.join(mac_parts)
                
        except Exception:
            return None
        return None

    def format_flags(self, groups):
        """Format group flags in a consistent order"""
        return ' '.join(sorted(groups))
        
    def scan_network(self, network):
        """Scan an IPv6 network if it's within size limits"""
        try:
            net = ipaddress.IPv6Network(network, strict=False)
            
            if net.prefixlen < self.subnet_size_limit:
                print(f"\n[!] Network {network} too large (/{net.prefixlen}). Use --max-prefix to allow scanning networks larger than /{self.subnet_size_limit}")
                return
                
            total_addrs = 2 ** (128 - net.prefixlen)
            print(f"\n[*] Scanning network: {network}")
            print(f"[*] Network size: {total_addrs:,} addresses")
            
            def process_response(pkt):
                """Process response packets from ping"""
                if IPv6 in pkt and ICMPv6EchoReply in pkt:
                    src = pkt[IPv6].src
                    if '%' in src:
                        src = src.split('%')[0]
                    if src not in self.discovered_hosts:
                        mac = None
                        if Ether in pkt:
                            mac = pkt[Ether].src
                        self.discovered_hosts[src] = (mac, {'NET'})
                        print(f"[+] Host discovered via network scan: {src}")
            
            # Start sniffer for responses
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter="icmp6[icmp6type] == 129",  # ICMPv6 Echo Reply
                prn=process_response,
                store=0
            )
            sniffer.start()
            
            # Send pings in batches
            batch_size = 50
            addrs = list(net.hosts())
            for i in range(0, len(addrs), batch_size):
                batch = addrs[i:i + batch_size]
                for addr in batch:
                    # Send ICMPv6 echo request
                    ping = IPv6(dst=str(addr))/ICMPv6EchoRequest()
                    send(ping, verbose=0)
                time.sleep(self.probe_wait)
                
            # Wait for final responses
            time.sleep(self.probe_wait * 2)
            sniffer.stop()
                
        except Exception as e:
            print(f"\n[-] Error scanning network {network}: {str(e)}")
            import traceback
            traceback.print_exc()

    def probe_solicited_node(self):
        """Probe solicited-node multicast addresses"""
        print("\n" + "-" * 80)
        print("[*] Starting solicited-node multicast scan")
        print("-" * 80 + "\n")

        def expand_ipv6(addr):
            """Expand :: notation to full IPv6 address"""
            if "::" in addr:
                addr = ipaddress.IPv6Address(addr).exploded
            return addr

        def make_solicit_addr(last_24):
            """Create properly formatted solicited-node multicast address"""
            last_part = format(int(last_24, 16), '06x')  # Ensure 6 hex digits
            return f"ff02:0000:0000:0000:0000:0001:ff{last_part[:2]}:{last_part[2:]}"
        
        def process_packet(pkt):
            if IPv6 in pkt and (ICMPv6ND_NA in pkt or ICMPv6ND_NS in pkt):
                src = pkt[IPv6].src
                if '%' in src:
                    src = src.split('%')[0]
                if src not in self.discovered_hosts:
                    mac = None
                    if ICMPv6NDOptSrcLLAddr in pkt:
                        mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                    elif Ether in pkt:
                        mac = pkt[Ether].src
                    self.discovered_hosts[src] = (mac, {'SOL'})
                    print(f"[+] Host discovered via solicited-node: {src}")
                else:
                    self.discovered_hosts[src][1].add('SOL')
        
        # Start sniffer for responses
        sniffer = AsyncSniffer(
            iface=self.interface,
            filter="icmp6",
            prn=process_packet,
            store=0
        )
        sniffer.start()
        
        # Get our link-local address for the interface
        if_addrs = netifaces.ifaddresses(self.interface)
        our_addr = None
        if netifaces.AF_INET6 in if_addrs:
            for addr in if_addrs[netifaces.AF_INET6]:
                if 'addr' in addr and addr['addr'].startswith('fe80:'):
                    our_addr = addr['addr'].split('%')[0]
                    break
        
        if not our_addr:
            print("[-] Could not find link-local address for interface")
            return
            
        # Expand our source address
        our_addr = expand_ipv6(our_addr)
            
        try:
            # Create raw socket for sending NS packets
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 
                        socket.if_nametoindex(self.interface))
            
            # Generate solicited-node multicast addresses from discovered hosts
            for host in list(self.discovered_hosts.keys()):
                try:
                    addr = ipaddress.IPv6Address(host)
                    # Get last 24 bits of address
                    last_24 = format(int(addr) & 0xFFFFFF, '06x')
                    # Create solicited-node multicast address
                    solicit = make_solicit_addr(last_24)
                    
                    # Debug print
                    print(f"[*] Probing {solicit}")
                    print(f"[*] Source address: {our_addr}")
                    
                    # Create ICMPv6 Neighbor Solicitation message
                    icmp_type = 135  # Neighbor Solicitation
                    icmp_code = 0
                    icmp_cksum = 0
                    icmp_reserved = 0
                    target_addr = socket.inet_pton(socket.AF_INET6, expand_ipv6(host))
                    
                    # Source Link-Layer Address option
                    opt_type = 1
                    opt_len = 1  # Length in units of 8 octets
                    mac_bytes = bytes.fromhex(self.if_mac.replace(':', ''))
                    
                    # Build ICMPv6 packet with option
                    icmp_msg = struct.pack('!BBHI', icmp_type, icmp_code, icmp_cksum, icmp_reserved) + \
                            target_addr + \
                            struct.pack('!BB', opt_type, opt_len) + mac_bytes
                    
                    # Calculate checksum (requires IPv6 pseudo-header)
                    pseudo_header = socket.inet_pton(socket.AF_INET6, our_addr) + \
                                socket.inet_pton(socket.AF_INET6, solicit) + \
                                struct.pack('!I', len(icmp_msg)) + \
                                b'\x00\x00\x00' + struct.pack('!B', socket.IPPROTO_ICMPV6)
                    
                    checksum = in6_chksum(socket.IPPROTO_ICMPV6, IPv6(src=our_addr, dst=solicit), icmp_msg)
                    
                    # Insert checksum into message
                    icmp_msg = icmp_msg[:2] + struct.pack('!H', checksum) + icmp_msg[4:]
                    
                    # Send packet
                    sock.sendto(icmp_msg, (f"{solicit}%{self.interface}", 0, 0, 
                            socket.if_nametoindex(self.interface)))
                    
                    time.sleep(self.probe_wait)
                    
                except Exception as e:
                    print(f"[-] Error probing {host}: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    
            sock.close()
            
        except Exception as e:
            print(f"[-] Error during solicited-node scan: {str(e)}")
            import traceback
            traceback.print_exc()
        
        # Wait for final responses
        time.sleep(self.probe_wait * 2)
        sniffer.stop()

    def probe_multicast_neighbor_solicitation(self):
        """Probe multicast targets using ICMPv6 Neighbor Solicitation messages"""
        print("\n" + "-" * 80)
        print("[*] Starting ICMPv6 multicast Neighbor Solicitation discovery...")
        print("-" * 80)
        
        current_group = None  # Track current group being probed
        addr_padding = 45  # Initial padding length for IPv6 addresses
        
        def process_packet(pkt):
            """Process captured packets"""
            if IPv6 in pkt:
                if (ICMPv6EchoReply in pkt or 
                    ICMPv6ND_NA in pkt or 
                    ICMPv6ND_NS in pkt):
                    src = pkt[IPv6].src
                    if '%' in src:
                        src = src.split('%')[0]
                    
                    # Process the packet
                    src = pkt[IPv6].src
                    if '%' in src:
                        src = src.split('%')[0]
                    
                    # Get MAC address
                    mac = None
                    if Ether in pkt and pkt[Ether].src != "00:00:00:00:00:00":
                        mac = pkt[Ether].src
                    if not mac:
                        mac = self.extract_mac_from_ipv6(src)
                    
                    # Add or update host
                    if src not in self.discovered_hosts:
                        self.discovered_hosts[src] = (mac, set())
                    
                    # If we're in a multicast probe, add the flag
                    if current_group and current_group in self.multicast_groups:
                        current_flag = self.multicast_groups[current_group]
                        self.discovered_hosts[src][1].add(current_flag)
                        padding = " " * (addr_padding - len(src))
                        mac_str = f"    {self.discovered_hosts[src][0]}" if self.discovered_hosts[src][0] else "    "
                        flags = self.format_flags(self.discovered_hosts[src][1])
                        print(f"[+] {src}{padding}{mac_str}    {flags}")

                    # Always add the current group flag if it exists
                    if current_group and current_group in self.multicast_groups:
                        is_new = src not in self.discovered_hosts
                        current_flag = self.multicast_groups[current_group]
                        
                        if is_new:
                            self.discovered_hosts[src] = (mac, {current_flag})
                        else:
                            self.discovered_hosts[src][1].add(current_flag)
                            
                        padding = " " * (addr_padding - len(src))
                        mac_str = f"    {self.discovered_hosts[src][0]}" if self.discovered_hosts[src][0] else "    "
                        flags = self.format_flags(self.discovered_hosts[src][1])
                        print(f"[+] {src}{padding}{mac_str}    {flags}")
        
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter="icmp6",
                prn=process_packet,
                store=0
            )
            sniffer.start()
            
            sock = self.create_icmp6_socket()
            if not sock:
                return
            
            for group, description in self.multicast_groups.items():
                current_group = group  # Set current group being probed
                dst = f"{group}%{self.interface}"
                print(f"\n[*] Probing {description} group ({group})")
                
                for i in range(2):
                    try:
                        # Send Neighbor Solicitation
                        icmp_type = 135  # NS
                        icmp_code = 0
                        icmp_checksum = 0
                        icmp_reserved = 0
                        target_addr = socket.inet_pton(socket.AF_INET6, "::")  # Empty target address
                        opt_type = 1  # Source Link-Layer Address
                        opt_len = 1   # Length in 8-octet units
                        mac_bytes = bytes.fromhex(self.if_mac.replace(':', ''))
                        
                        ns_packet = struct.pack('!BBHI', icmp_type, icmp_code,
                                            icmp_checksum, icmp_reserved) + \
                                target_addr + \
                                struct.pack('!BB', opt_type, opt_len) + mac_bytes
                        
                        sock.sendto(ns_packet, (dst.split('%')[0], 0, 0,
                                socket.if_nametoindex(self.interface)))
                    
                    except Exception as e:
                        print(f"[-] Error sending probe: {str(e)}")
                    
                    time.sleep(self.probe_wait)
            
            current_group = None  # Clear current group
            time.sleep(2)
            sniffer.stop()
            
            if sock:
                sock.close()
                
        except Exception as e:
            print(f"[-] Error during scanning: {str(e)}")

    def probe_multicast_ping(self):
        """Probe multicast targets using IPv6 ping messages"""
        print("\n" + "-" * 80)
        print("[*] Starting IPv6 multicast ping discovery...")
        print("-" * 80)
        
        current_group = None  # Track current group being probed
        addr_padding = 45  # Initial padding length for IPv6 addresses
        
        def process_packet(pkt):
            """Process captured packets"""
            if IPv6 in pkt:
                if (ICMPv6EchoReply in pkt or 
                    ICMPv6ND_NA in pkt or 
                    ICMPv6ND_NS in pkt):
                    src = pkt[IPv6].src
                    if '%' in src:
                        src = src.split('%')[0]
                    
                    # Process the packet
                    src = pkt[IPv6].src
                    if '%' in src:
                        src = src.split('%')[0]
                    
                    # Get MAC address
                    mac = None
                    if Ether in pkt and pkt[Ether].src != "00:00:00:00:00:00":
                        mac = pkt[Ether].src
                    if not mac:
                        mac = self.extract_mac_from_ipv6(src)
                    
                    # Add or update host
                    if src not in self.discovered_hosts:
                        self.discovered_hosts[src] = (mac, set())
                    
                    # If we're in a multicast probe, add the flag
                    if current_group and current_group in self.multicast_groups:
                        current_flag = self.multicast_groups[current_group]
                        self.discovered_hosts[src][1].add(current_flag)
                        padding = " " * (addr_padding - len(src))
                        mac_str = f"    {self.discovered_hosts[src][0]}" if self.discovered_hosts[src][0] else "    "
                        flags = self.format_flags(self.discovered_hosts[src][1])
                        print(f"[+] {src}{padding}{mac_str}    {flags}")

                    # Always add the current group flag if it exists
                    if current_group and current_group in self.multicast_groups:
                        is_new = src not in self.discovered_hosts
                        current_flag = self.multicast_groups[current_group]
                        
                        if is_new:
                            self.discovered_hosts[src] = (mac, {current_flag})
                        else:
                            self.discovered_hosts[src][1].add(current_flag)
                            
                        padding = " " * (addr_padding - len(src))
                        mac_str = f"    {self.discovered_hosts[src][0]}" if self.discovered_hosts[src][0] else "    "
                        flags = self.format_flags(self.discovered_hosts[src][1])
                        print(f"[+] {src}{padding}{mac_str}    {flags}")
        
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter="icmp6",
                prn=process_packet,
                store=0
            )
            sniffer.start()
            
            sock = self.create_icmp6_socket()
            if not sock:
                return
            
            for group, description in self.multicast_groups.items():
                current_group = group  # Set current group being probed
                dst = f"{group}%{self.interface}"
                print(f"\n[*] Probing {description} group ({group})")
                
                for i in range(2):
                    try:
                        # Send ping
                        icmp_type = 128
                        icmp_code = 0
                        icmp_checksum = 0
                        icmp_id = os.getpid() & 0xFFFF
                        icmp_seq = i
                        icmp_data = b"PROBE"
                        
                        icmp_packet = struct.pack('!BBHHH', icmp_type, icmp_code,
                                                icmp_checksum, icmp_id, icmp_seq) + icmp_data
                        
                        sock.sendto(icmp_packet, (dst.split('%')[0], 0, 0,
                                   socket.if_nametoindex(self.interface)))
                        
                    except Exception as e:
                        print(f"[-] Error sending probe: {str(e)}")
                    
                    time.sleep(self.probe_wait)
            
            current_group = None  # Clear current group
            time.sleep(2)
            sniffer.stop()
            
            if sock:
                sock.close()
                
        except Exception as e:
            print(f"[-] Error during scanning: {str(e)}")

    def print_results(self):
        """Print discovered hosts summary"""
        print("\n" + "=" * 80)
        print("[+] Discovered Hosts Summary:")
        print("=" * 80)
        if not self.discovered_hosts:
            print("  No hosts discovered")
            print("\nTroubleshooting tips:")
            print("1. Verify IPv6 connectivity:")
            print(f"   ifconfig {self.interface} inet6")
            print("2. Try manual test:")
            print(f"   ping6 ff02::1%{self.interface}")
            print("3. Check system firewall settings")
        else:
            # Find the longest IPv6 address for alignment
            max_addr_len = max(len(addr) for addr in self.discovered_hosts.keys())
            
            link_local = [(addr, info) for addr, info in self.discovered_hosts.items() 
                         if addr.startswith('fe80:')]
            global_addrs = [(addr, info) for addr, info in self.discovered_hosts.items() 
                          if not addr.startswith('fe80:')]
            
            if link_local:
                print("\nLink-local addresses:")
                for addr, (mac, groups) in sorted(link_local):
                    padding = " " * (max_addr_len - len(addr))
                    mac_str = f"    {mac}" if mac else "    "
                    flags = self.format_flags(groups)
                    print(f"{addr}{padding}{mac_str}    {flags}")
                    
            if global_addrs:
                print("\nGlobal addresses:")
                for addr, (mac, groups) in sorted(global_addrs):
                    padding = " " * (max_addr_len - len(addr))
                    mac_str = f"    {mac}" if mac else "    "
                    flags = self.format_flags(groups)
                    print(f"{addr}{padding}{mac_str}    {flags}")
                    
            print(f"\nTotal hosts discovered: {len(self.discovered_hosts)}")
            print("\nFlags explanation:")
            print("  ALL   - All Nodes (ff02::1)")
            print("  RTR   - All Routers (ff02::2)")
            print("  DHCP  - All DHCP Servers (ff02::1:2)")
            print("  MLDv2 - All MLDv2-capable Routers (ff02::16)")
            print("  RELAY - All DHCP Relays (ff02::1:3)")
            print("  SOL   - Responded to Solicited-Node multicast")
            print("  NET   - Discovered via network scan")

def main():
    parser = argparse.ArgumentParser(
        description='IPv6 network scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('interface', nargs='?', help='Network interface to scan')
    parser.add_argument('-l', '--list', action='store_true', 
                       help='List active network interfaces')
    parser.add_argument('-w', '--wait', type=float, default=0.5,
                       help='Time to wait for responses after each multicast probe (default: 0.5s)')
    parser.add_argument('-s', '--solicit', action='store_true',
                       help='Include solicited-node multicast scanning')
    parser.add_argument('-n', '--network', action='store_true',
                       help='Scan networks of discovered hosts (default: /125 = 8 addresses)')
    parser.add_argument('--max-prefix', type=int, default=125,
                       help='Maximum prefix length for network scanning (example: 120 for /120 = 256 addresses). \n' +
                            'Smaller number = larger network = longer scan time. Default: 125 for /125 = 8 addresses')
    
    args = parser.parse_args()

    if args.max_prefix != 125 and not args.network:  # 125 is the default value
        print("Error: --max-prefix can only be used with -n/--network option")
        sys.exit(1)

    if args.list:
        IPv6Scanner.list_interfaces()
        sys.exit(0)
        
    if not args.interface:
        parser.print_help()
        print("\nNo interface specified. Available interfaces:\n")
        IPv6Scanner.list_interfaces()
        sys.exit(1)
        
    # Validate prefix length
    if args.max_prefix < 1 or args.max_prefix > 128:
        print("Error: Prefix length must be between 1 and 128")
        sys.exit(1)
        
    scanner = IPv6Scanner(args.interface)
    scanner.probe_wait = args.wait
    scanner.solicit_scan = args.solicit
    scanner.network_scan = args.network
    scanner.subnet_size_limit = args.max_prefix
    
    # First do multicast neighbor solicitation scan
    scanner.probe_multicast_neighbor_solicitation()

    # Then do multicast ping scan
    scanner.probe_multicast_ping()
    
    # Then do solicited-node scan if requested
    if args.solicit:
        scanner.probe_solicited_node()
        
    # Finally do network scan if requested
    if args.network:
        print("\n" + "-" * 80)
        print("[*] Scanning nearby networks...")
        print("-" * 80)
        discovered_networks = set()
        for addr in scanner.discovered_hosts:
            try:
                network = ipaddress.IPv6Network(f"{addr}/{scanner.subnet_size_limit}", strict=False)
                discovered_networks.add(str(network))
            except Exception:
                continue
        
        for network in discovered_networks:
            scanner.scan_network(network)
    
    scanner.print_results()

if __name__ == "__main__":
    main()