#!/usr/bin/env python3
"""
IPv6 Network Scanner

The scanner supports IPv6 host discovery using:
- Multicast group discovery
- Neighbor solicitation
- Solicited-node multicast scanning
- Network scanning

The scanner provides information about discovered hosts, their MAC addresses,
and multicast group memberships.

Required packages:
    - scapy
    - netifaces
    - ipaddress

Usage:
    sudo python scanner.py [-h] [-l] [-p] [-n] [-s] [-k] [--group-all-nodes] [--group-routers] [--group-dhcp] [--group-mldv2] [--group-relay] [-a] [-g] [-w WAIT] [--subnet-size SUBNET_SIZE] [interface]

Author: D. Matscheko
License: GPLv3
Version: 0.0.5
"""

import sys
import os
import socket
import time
import struct
import argparse
import ipaddress
from typing import Dict, Set, Tuple, Optional, Union, Callable, List, Type
import netifaces
from scapy.all import (
    conf, AsyncSniffer, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
    ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, Ether, in6_chksum,
    send, Packet
)
from collections import defaultdict
from contextlib import contextmanager


class DiscoveryState:
    """Manages state during discovery process."""
    def __init__(self, addr_padding: int = 45):
        self.current_group: Optional[str] = None
        self.addr_padding: int = addr_padding
        self.src_addr: Optional[str] = None


class ProbeType:
    """
    Represents a type of IPv6 probe with its configuration.
    
    Attributes:
        name: Unique identifier for the probe type
        description: Human-readable description of what this probe does
        packet_creator: Function that creates the probe packet
        response_types: List of scapy packet types to expect as responses
        needs_src_addr: Whether this probe requires a source address
        handler: Function that handles sending the probes
    """
    def __init__(self, *, 
                 name: str,
                 description: str,
                 packet_creator: Callable,
                 response_types: List[Type[Packet]],
                 needs_src_addr: bool = False,
                 handler: Optional[Callable] = None):
        self.name = name
        self.description = description
        self.packet_creator = packet_creator
        self.response_types = response_types
        self.needs_src_addr = needs_src_addr
        self.handler = handler


class ICMPv6PacketBuilder:
    """Builder for ICMPv6 packets."""
    # ICMPv6 type constants
    ICMPV6_ECHO_REQUEST = 128
    ICMPV6_NS = 135

    def __init__(self, if_mac: str):
        """Initialize the packet builder with interface MAC address."""
        self.if_mac = if_mac
        self.mac_bytes = bytes.fromhex(if_mac.replace(':', ''))

    def create_ping(self, seq: int, src_addr: str, target_addr: str = "ff02::1") -> bytes:
        """
        Create an ICMPv6 Echo Request packet.
        If no target_addr is given, creates a multicast ping.
        Otherwise creates a unicast ping to the specified target.
        """
        payload = struct.pack('!HH', os.getpid() & 0xFFFF, seq)
        
        return self._create_icmpv6_packet(
            icmp_type=self.ICMPV6_ECHO_REQUEST,
            src_addr=src_addr,
            dst_addr=target_addr,
            payload=payload
        )

    def create_ns(self, seq: int, src_addr: str, target_addr: str = "ff02::1") -> bytes:
        """
        Create a Neighbor Solicitation packet.
        If no target_addr is given, creates a multicast NS.
        Otherwise creates a unicast NS to the specified target.
        """
        target = socket.inet_pton(socket.AF_INET6, target_addr)
        reserved = b'\x00' * 4
        lladdr_opt = struct.pack('!BB', 1, 1) + self.mac_bytes
        payload = reserved + target + lladdr_opt
        
        return self._create_icmpv6_packet(
            icmp_type=self.ICMPV6_NS,
            src_addr=src_addr,
            dst_addr=target_addr,
            payload=payload
        )

    def _create_icmpv6_packet(self, icmp_type: int, src_addr: str, dst_addr: str, 
                            payload: bytes = b'', icmp_code: int = 0) -> bytes:
        """Create an ICMPv6 packet with checksum."""
        packet = struct.pack('!BBH', icmp_type, icmp_code, 0) + payload
        checksum = in6_chksum(
            socket.IPPROTO_ICMPV6,
            IPv6(src=src_addr, dst=dst_addr),
            packet
        )
        return packet[:2] + struct.pack('!H', checksum) + packet[4:]


class IPv6Scanner:
    """
    IPv6 network scanner implementing multiple discovery methods.
    
    This class provides functionality for:
    - Multicast group discovery
    - Neighbor solicitation
    - Network scanning
    - Solicited-node multicast scanning
    
    Attributes:
        interface (str): Network interface to use for scanning
        discovered_hosts (dict): Mapping of IP addresses to (MAC, groups) tuples
        probe_wait (float): Wait time between probes in seconds
        network_scan (bool): Whether to perform network scanning
        subnet_size (int): Minimum prefix length for network scanning
        solicit_scan (bool): Whether to perform solicited-node scanning
    """
    
    MULTICAST_GROUPS = {
        'ff02::1': 'ALL',      # All Nodes
        'ff02::2': 'RTR',      # All Routers
        'ff02::1:2': 'DHCP',   # All DHCP Servers
        'ff02::16': 'MLDv2',   # All MLDv2-capable Routers
        'ff02::1:3': 'RELAY'   # All DHCP Relays
    }

    def __init__(self, interface: str):
        """
        Initialize the IPv6Scanner.

        Args:
            interface: Network interface name to use for scanning
        """
        self.interface = interface
        self.discovered_hosts: Dict[str, Tuple[Optional[str], Set[str]]] = {}
        self.probe_wait = 0.5  # Default wait time between probes
        self.network_scan = False
        self.subnet_size = 120  # Default prefix length
        self.solicit_scan = False
        
        conf.verb = 0
        self.if_mac = self._get_interface_mac()
        self.packet_builder = ICMPv6PacketBuilder(self.if_mac)
        
        # Initialize probe types
        self.probes = self._init_probes()

    def _init_probes(self) -> Dict[str, ProbeType]:
        """Initialize available probe types."""
        probes = {
            probe.name: probe for probe in [
                ProbeType(
                    name='ping',
                    description='ICMPv6 Multicast Groups Echo Request',
                    packet_creator=self.packet_builder.create_ping,
                    response_types=[ICMPv6EchoReply],
                    handler=self._handle_standard_probe
                ),
                ProbeType(
                    name='ns',
                    description='ICMPv6 Multicast Groups Neighbor Solicitation',
                    packet_creator=self.packet_builder.create_ns,
                    response_types=[ICMPv6ND_NA, ICMPv6ND_NS],
                    handler=self._handle_standard_probe
                ),
                ProbeType(
                    name='solicit',
                    description='ICMPv6 Solicited-Node Multicast',
                    packet_creator=self.packet_builder.create_ns,
                    response_types=[ICMPv6ND_NA, ICMPv6ND_NS],
                    needs_src_addr=True,
                    handler=self._handle_solicited_node_probe
                ),
                ProbeType(
                    name='network',
                    description='ICMPv6 Nearby Network',
                    packet_creator=self.packet_builder.create_ping,
                    response_types=[ICMPv6EchoReply],
                    handler=self._handle_network_probe
                )
            ]
        }
        return probes

    def _get_interface_mac(self) -> str:
        """
        Get the MAC address of the specified interface.
        
        Returns:
            str: MAC address or default "00:00:00:00:00:00" if not found
        """
        try:
            if_addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_LINK in if_addrs:
                return if_addrs[netifaces.AF_LINK][0]['addr']
        except Exception:
            pass
        return "00:00:00:00:00:00"

    @staticmethod
    def list_interfaces() -> list:
        """
        List active network interfaces and their addresses.
        
        Returns:
            list: List of active interface names
        """
        print("[*] Active network interfaces:")
        active_interfaces = []
        
        for iface in netifaces.interfaces():
            # Skip loopback interfaces
            if iface.startswith(('lo', 'localhost')):
                continue
                
            addrs = netifaces.ifaddresses(iface)
            has_addresses = (
                (netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]) or
                (netifaces.AF_INET6 in addrs and [
                    a for a in addrs[netifaces.AF_INET6]
                    if not a['addr'].startswith('fe80:')
                ])
            )
            
            if has_addresses:
                print(f"\nInterface: {iface}")
                active_interfaces.append(iface)
                
                # Print IPv4 addresses
                if netifaces.AF_INET in addrs:
                    print("  IPv4 addresses:")
                    for addr in addrs[netifaces.AF_INET]:
                        print(f"    {addr['addr']}")
                
                # Print IPv6 addresses
                if netifaces.AF_INET6 in addrs:
                    print("  IPv6 addresses:")
                    for addr in addrs[netifaces.AF_INET6]:
                        if not addr['addr'].startswith('fe80:'):
                            print(f"    {addr['addr']}")
                
                # Print MAC address
                if netifaces.AF_LINK in addrs:
                    print("  MAC address:")
                    print(f"    {addrs[netifaces.AF_LINK][0]['addr']}")
        
        if not active_interfaces:
            print("\nNo active interfaces with IPv4/IPv6 addresses found!")
            
        return active_interfaces

    @contextmanager
    def _create_socket(self) -> socket.socket:
        """Create and configure ICMPv6 socket as context manager."""
        sock = self.create_icmp6_socket()
        if not sock:
            raise RuntimeError("Failed to create ICMPv6 socket")
        try:
            yield sock
        finally:
            sock.close()

    def create_icmp6_socket(self) -> Optional[socket.socket]:
        """
        Create a raw ICMPv6 socket with appropriate options.
        
        Returns:
            Optional[socket.socket]: Configured socket or None if creation fails
        """
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

    @staticmethod
    def extract_mac_from_ipv6(ipv6_addr: str) -> Optional[str]:
        """
        Extract MAC address from EUI-64 based IPv6 address.
        
        Args:
            ipv6_addr: IPv6 address to extract MAC from
            
        Returns:
            Optional[str]: MAC address or None if extraction fails
        """
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

    @staticmethod
    def format_flags(groups: Set[str]) -> str:
        """Format group flags in a consistent order."""
        return ' '.join(sorted(groups))

    def probe_multicast(self, probe: Union[str, ProbeType]) -> None:
        """
        Enhanced multicast probing with unified packet handling.
        
        Args:
            probe: Either a probe type name (str) or ProbeType instance
        """
        # Convert string to ProbeType if necessary
        if isinstance(probe, str):
            if probe not in self.probes:
                raise ValueError(f"Invalid probe type: {probe}")
            probe = self.probes[probe]
            
        state = DiscoveryState()
        
        # Initialize probe-specific requirements
        if probe.needs_src_addr:
            state.src_addr = self._get_link_local_address()
            if not state.src_addr:
                print("[-] Could not find link-local address for interface")
                return
            state.src_addr = str(ipaddress.IPv6Address(state.src_addr))
        
        self._print_probe_header(probe.description)
        
        try:
            with self._setup_sniffer(probe, state) as sniffer:
                with self._create_socket() as sock:
                    probe.handler(sock, probe, state)
                
                time.sleep(self.probe_wait * 2)
                
        except Exception as e:
            print(f"[-] Error during {probe.description} scanning: {str(e)}")

    @contextmanager
    def _setup_sniffer(self, probe: ProbeType, state: DiscoveryState) -> AsyncSniffer:
        """Set up packet sniffer with appropriate filters."""
        def process_packet(pkt):
            if not IPv6 in pkt:
                return
            
            # Filtering received packets is not necessary since the goal is to find ans many addresses as possible:
            # if not any(resp_type in pkt for resp_type in probe.response_types):
            #     return
            
            src = pkt[IPv6].src.split('%')[0]
            mac = self._extract_mac_from_packet(pkt)
            
            self._update_discovered_host(src, mac, probe, state)
            
        sniffer = AsyncSniffer(
            iface=self.interface,
            filter="icmp6",
            prn=process_packet,
            store=0
        )
        sniffer.start()
        try:
            yield sniffer
        finally:
            time.sleep(self.probe_wait * 2)
            sniffer.stop()

    def _handle_standard_probe(self, sock: socket.socket, probe: ProbeType, 
                            state: DiscoveryState) -> None:
        """Unified handler for default probe types."""
        # Handle standard multicast probes
        for group, description in self.MULTICAST_GROUPS.items():
            state.current_group = group
            print(f"\n[*] Probing {description} group ({group})")
            
            for i in range(2):
                try:
                    packet = probe.packet_creator(seq=i, src_addr=state.src_addr)
                    self._send_probe(sock, group, packet)
                except Exception as e:
                    print(f"[-] Error sending probe: {str(e)}")
                    continue
                
                time.sleep(self.probe_wait)

    def _handle_solicited_node_probe(self, sock: socket.socket, probe: ProbeType, 
                            state: DiscoveryState) -> None:
        print()
        # Handle solicited-node probes
        for host in list(self.discovered_hosts.keys()):
            try:
                solicit_addr = self._calculate_solicited_node_addr(host)
                state.current_group = solicit_addr
                
                print(f"[*] Probing {host} via {solicit_addr}")
                
                packet = probe.packet_creator(seq=0, src_addr=state.src_addr, target_addr=solicit_addr)
                self._send_probe(sock, solicit_addr, packet)
                
            except Exception as e:
                print(f"[-] Error probing {host}: {str(e)}")
                continue

    def _handle_network_probe(self, sock: socket.socket, probe: ProbeType, 
                            state: DiscoveryState) -> None:
        """Handler for network scanning probes."""
        discovered_networks = set()
        for addr in self.discovered_hosts:
            try:
                network = ipaddress.IPv6Network(f"{addr}/{self.subnet_size}", 
                                                strict=False)
                discovered_networks.add(network)
            except Exception:
                continue

        for network in discovered_networks:
            try:
                state.current_group="NET"
                print(f"\n[*] Scanning network: {network}")
                print(f"[*] Network size: {2 ** (128 - network.prefixlen):,} addresses")

                # Send probes to each address in the network
                for addr in network.hosts():
                    addr_str = str(addr)
                    try:
                        packet = probe.packet_creator(seq=1, src_addr=state.src_addr, target_addr=addr_str)
                        print(f"[*] Probing {addr_str}")
                        self._send_probe(sock, addr_str, packet)
                    except Exception as e:
                        print(f"[-] Error probing {addr_str}: {str(e)}")
                        continue

            except Exception as e:
                print(f"[-] Error during network scan: {str(e)}")

    def _send_probe(self, sock: socket.socket, dst: str, packet: bytes) -> None:
        """Send probe packet to destination."""
        sock.sendto(packet, (f"{dst}%{self.interface}", 0, 0,
                socket.if_nametoindex(self.interface)))
        time.sleep(self.probe_wait)

    def _extract_mac_from_packet(self, pkt) -> Optional[str]:
        """Extract MAC address from packet in priority order."""
        if ICMPv6NDOptSrcLLAddr in pkt:
            return pkt[ICMPv6NDOptSrcLLAddr].lladdr
        if Ether in pkt and pkt[Ether].src != "00:00:00:00:00:00":
            return pkt[Ether].src
        return self.extract_mac_from_ipv6(pkt[IPv6].src)

    def _update_discovered_host(self, src: str, mac: Optional[str], 
                            probe: ProbeType, state: DiscoveryState) -> None:
        """Update discovered host information."""
        is_new = src not in self.discovered_hosts
        if is_new:
            self.discovered_hosts[src] = (mac, set())
        
        # Add appropriate flag
        if probe.name == 'solicit':
            self.discovered_hosts[src][1].add('SOL')
        elif state.current_group in self.MULTICAST_GROUPS:
            self.discovered_hosts[src][1].add(self.MULTICAST_GROUPS[state.current_group])
        elif state.current_group == "NET":
            self.discovered_hosts[src][1].add("NET")

        # Print discovery
        self._print_discovery(src, mac, state.addr_padding)

    def _print_discovery(self, src: str, mac: Optional[str], padding: int) -> None:
        """Print discovered host information."""
        addr_padding = " " * (padding - len(src))
        mac_str = f"    {mac}" if mac else "    "
        flags = self.format_flags(self.discovered_hosts[src][1])
        print(f"[+] {src}{addr_padding}{mac_str}    {flags}")

    def _get_link_local_address(self) -> Optional[str]:
        """Get link-local address for the interface."""
        if_addrs = netifaces.ifaddresses(self.interface)
        if netifaces.AF_INET6 in if_addrs:
            for addr in if_addrs[netifaces.AF_INET6]:
                if 'addr' in addr and addr['addr'].startswith('fe80:'):
                    return addr['addr'].split('%')[0]
        return None

    @staticmethod
    def _calculate_solicited_node_addr(host: str) -> str:
        """Calculate solicited-node multicast address for a host."""
        addr = ipaddress.IPv6Address(host)
        last_24 = format(int(addr) & 0xFFFFFF, '06x')
        return f"ff02::1:ff{last_24[-6:-4]}:{last_24[-4:]}"

    @staticmethod
    def _print_probe_header(description: str) -> None:
        """Print header for probe operation."""
        print("\n" + "-" * 80)
        print(f"[*] Starting {description} discovery...")
        print("-" * 80)

    def print_results(self) -> None:
        """Print discovered hosts summary."""
        print("\n" + "=" * 80)
        print("[+] Discovered Hosts Summary:")
        print("=" * 80)
        
        if not self.discovered_hosts:
            self._print_empty_results()
            return
            
        # Find the longest IPv6 address for alignment
        max_addr_len = max(len(addr) for addr in self.discovered_hosts.keys())
        
        # Split hosts into link-local and global
        link_local = [(addr, info) for addr, info in self.discovered_hosts.items() 
                     if addr.startswith('fe80:')]
        global_addrs = [(addr, info) for addr, info in self.discovered_hosts.items() 
                      if not addr.startswith('fe80:')]
        
        # Print results
        self._print_address_section("Link-local addresses:", link_local, max_addr_len)
        self._print_address_section("Global addresses:", global_addrs, max_addr_len)
        
        print(f"\nTotal hosts discovered: {len(self.discovered_hosts)}")
        self._print_flags_explanation()

    def _print_empty_results(self) -> None:
        """Print message when no hosts are discovered."""
        print("  No hosts discovered")
        print("\nTroubleshooting tips:")
        print("1. Verify IPv6 connectivity:")
        print(f"   ifconfig {self.interface} inet6")
        print("2. Try manual test:")
        print(f"   ping6 ff02::1%{self.interface}")
        print("3. Check system firewall settings and verify that python runs as root")

    def _print_address_section(self, title: str, addresses: list, padding: int) -> None:
        """Print a section of addresses with consistent formatting."""
        if addresses:
            print(f"\n{title}")
            for addr, (mac, groups) in sorted(addresses):
                addr_padding = " " * (padding - len(addr))
                mac_str = f"    {mac}" if mac else "    "
                flags = self.format_flags(groups)
                print(f"{addr}{addr_padding}{mac_str}    {flags}")

    def _print_flags_explanation(self) -> None:
        """Print explanation of flag meanings."""
        print("\nFlags explanation:")
        print("  ALL   - All Nodes (ff02::1)")
        print("  RTR   - All Routers (ff02::2)")
        print("  DHCP  - All DHCP Servers (ff02::1:2)")
        print("  MLDv2 - All MLDv2-capable Routers (ff02::16)")
        print("  RELAY - All DHCP Relays (ff02::1:3)")
        print("  SOL   - Responded to Solicited-Node multicast")
        print("  NET   - Discovered via network scan")


def main():
    """Main entry point for the IPv6 scanner."""
    parser = argparse.ArgumentParser(
        description='IPv6 network scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Basic options
    basic_group = parser.add_argument_group('basic options')
    basic_group.add_argument('interface', nargs='?', help='Network interface to scan')
    basic_group.add_argument('-l', '--list', action='store_true', 
                          help='List active network interfaces')
    
    # Discovery methods
    discovery_group = parser.add_argument_group('discovery methods')
    discovery_group.add_argument('-p', '--ping', action='store_true',
                             help='Enable ICMPv6 Multicast Groups Echo Request discovery')
    discovery_group.add_argument('-n', '--ns', action='store_true',
                             help='Enable ICMPv6 Multicast Groups Neighbor Solicitation discovery')
    discovery_group.add_argument('-s', '--solicit', action='store_true',
                             help='Include solicited-node multicast discovery')
    discovery_group.add_argument('-k', '--network', action='store_true',
                           help='Scan networks of discovered hosts (default: /125 = 8 addresses)')
    
    # Multicast groups
    group_group = parser.add_argument_group('multicast groups')
    group_group.add_argument('--group-all-nodes', action='store_true',
                          help='Probe all nodes = ALL group = ff02::1')
    group_group.add_argument('--group-routers', action='store_true',
                          help='Probe all routers = RTR group = ff02::2')
    group_group.add_argument('--group-dhcp', action='store_true',
                          help='Probe all DHCP servers = DHCP group = ff02::1:2')
    group_group.add_argument('--group-mldv2', action='store_true',
                          help='Probe all MLDv2-capable routers = MLDv2 group = ff02::16')
    group_group.add_argument('--group-relay', action='store_true',
                          help='Probe all DHCP relays = RELAY group = ff02::1:3')

    # General options
    general_group = parser.add_argument_group('general options')
    general_group.add_argument('-a', '--all', action='store_true',
                           help='Enable all discovery methods and probe all multicast groups')
    general_group.add_argument('-g', '--all-groups', action='store_true',
                          help='Probe all multicast groups')
    
    # Advanced discovery options
    advanced_group = parser.add_argument_group('advanced discovery options')
    advanced_group.add_argument('-w', '--wait', type=float, default=0.5,
                          help='Time to wait for responses after each multicast probe (default: 0.5s)')
    advanced_group.add_argument('--subnet-size', type=int, default=125,
                           help='Subnet size is the prefix length for network scanning (example: 120 for /120 = 256 addresses). \n' +
                                'Smaller number = larger network = longer scan time. Default: 125 for /125 = 8 addresses')

    args = parser.parse_args()

    # Validate arguments
    if args.subnet_size != 125 and not args.network:
        print("Error: --subnet-size can only be used with -k/--network option")
        sys.exit(1)

    if args.list:
        IPv6Scanner.list_interfaces()
        sys.exit(0)
        
    if not args.interface:
        parser.print_help()
        print("\nNo interface specified. Available interfaces:\n")
        IPv6Scanner.list_interfaces()
        sys.exit(1)
        
    if args.subnet_size < 1 or args.subnet_size > 128:
        print("Error: Prefix length must be between 1 and 128")
        sys.exit(1)

    # Initialize scanner
    scanner = IPv6Scanner(args.interface)
    scanner.probe_wait = args.wait
    scanner.solicit_scan = args.solicit or args.all
    scanner.network_scan = args.network or args.all
    scanner.subnet_size = args.subnet_size

    # Determine which groups to scan
    active_groups = set()
    if args.all_groups or args.all:
        # If all-groups/all is set, use all groups
        active_groups = set(scanner.MULTICAST_GROUPS.keys())
    else:
        # Add specifically requested groups
        if args.group_all_nodes:
            active_groups.add('ff02::1')
        if args.group_routers:
            active_groups.add('ff02::2')
        if args.group_dhcp:
            active_groups.add('ff02::1:2')
        if args.group_mldv2:
            active_groups.add('ff02::16')
        if args.group_relay:
            active_groups.add('ff02::1:3')
    if not active_groups:
        # If no specific groups are selected, use at least the ALL Nodes group (ff02::1)
        active_groups = {'ff02::1'}

    # Store active groups in scanner
    scanner.MULTICAST_GROUPS = {addr: desc for addr, desc in scanner.MULTICAST_GROUPS.items() 
                              if addr in active_groups}

    try:
        # Execute scanning sequence based on enabled methods
        if args.all or args.ping or not args.ns:
            # Run ping probe by default if no other method is specified
            scanner.probe_multicast(scanner.probes['ping'])

        if args.all or args.ns:
            scanner.probe_multicast(scanner.probes['ns'])

        if scanner.solicit_scan:
            scanner.probe_multicast(scanner.probes['solicit'])

        if scanner.network_scan:
            scanner.probe_multicast(scanner.probes['network'])

        scanner.print_results()

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        scanner.print_results()
    except Exception as e:
        print(f"\n[-] Error during scanning: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
