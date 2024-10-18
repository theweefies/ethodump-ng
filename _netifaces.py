#!/usr/bin/env python3

import os
import socket
import ctypes
import ipaddress

from ctypes import util
from typing import Optional

IFF_UP = 0x1           # Interface is up
IFF_BROADCAST = 0x2    # Valid broadcast address set
IFF_DEBUG = 0x4        # Internal debugging flag
IFF_LOOPBACK = 0x8     # Interface is a loopback
IFF_POINTOPOINT = 0x10 # Interface is a point-to-point link
IFF_NOTRAILERS = 0x20  # Avoid use of trailers
IFF_RUNNING = 0x40     # Resources are allocated
IFF_NOARP = 0x80       # No ARP protocol
IFF_PROMISC = 0x100    # Promiscuous mode
IFF_ALLMULTI = 0x200   # Receive all multicast packets
IFF_MASTER = 0x400     # Master of a load balancer
IFF_SLAVE = 0x800      # Slave of a load balancer
IFF_MULTICAST = 0x1000 # Supports multicast
IFF_PORTSEL = 0x2000   # Can set media type
IFF_AUTOMEDIA = 0x4000 # Auto media select active
IFF_DYNAMIC = 0x8000   # Dialup device with changing addresses

# ctypes structures to handle network interfaces
class sockaddr(ctypes.Structure):
    _fields_ = [('sa_family', ctypes.c_uint16), ('sa_data', ctypes.c_uint8 * 14)]

class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_uint16),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_uint8 * 4),
        ('sin_zero', ctypes.c_uint8 * 8),
    ]

class sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ('sin6_family', ctypes.c_uint16),
        ('sin6_port', ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr', ctypes.c_uint8 * 16),
        ('sin6_scope_id', ctypes.c_uint32),
    ]

class ifaddrs(ctypes.Structure):
    pass

ifaddrs._fields_ = [
    ('ifa_next', ctypes.POINTER(ifaddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(sockaddr)),
    ('ifa_netmask', ctypes.POINTER(sockaddr)),
    ('ifa_broadaddr', ctypes.POINTER(sockaddr)),
]

class sockaddr_ll(ctypes.Structure):
    _fields_ = [
        ('sll_family', ctypes.c_uint16),
        ('sll_protocol', ctypes.c_uint16),
        ('sll_ifindex', ctypes.c_int),
        ('sll_hatype', ctypes.c_uint16),
        ('sll_pkttype', ctypes.c_uint8),
        ('sll_halen', ctypes.c_uint8),
        ('sll_addr', ctypes.c_uint8 * 8)
    ]

libc = ctypes.CDLL(util.find_library("c"), use_errno=True)

def get_interface_flags(iface_name: str) -> str:
    """
    Retrieve and return interface flags for a given network interface.
    """
    addr = ctypes.POINTER(ifaddrs)()
    if libc.getifaddrs(ctypes.byref(addr)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

    current = addr
    flags = None
    while current:
        if current.contents.ifa_name.decode('utf-8') == iface_name:
            flags = current.contents.ifa_flags
            break
        current = current.contents.ifa_next
    libc.freeifaddrs(addr)

    if flags is None:
        raise ValueError(f"Could not find flags for interface {iface_name}")

    # Decode flags into human-readable form
    readable_flags = []
    if flags & IFF_UP:
        readable_flags.append("UP")
    if flags & IFF_BROADCAST:
        readable_flags.append("BROADCAST")
    if flags & IFF_DEBUG:
        readable_flags.append("DEBUG")
    if flags & IFF_LOOPBACK:
        readable_flags.append("LOOPBACK")
    if flags & IFF_POINTOPOINT:
        readable_flags.append("POINTOPOINT")
    if flags & IFF_NOTRAILERS:
        readable_flags.append("NOTRAILERS")
    if flags & IFF_RUNNING:
        readable_flags.append("RUNNING")
    if flags & IFF_NOARP:
        readable_flags.append("NOARP")
    if flags & IFF_PROMISC:
        readable_flags.append("PROMISC")
    if flags & IFF_ALLMULTI:
        readable_flags.append("ALLMULTI")
    if flags & IFF_MASTER:
        readable_flags.append("MASTER")
    if flags & IFF_SLAVE:
        readable_flags.append("SLAVE")
    if flags & IFF_MULTICAST:
        readable_flags.append("MULTICAST")
    if flags & IFF_PORTSEL:
        readable_flags.append("PORTSEL")
    if flags & IFF_AUTOMEDIA:
        readable_flags.append("AUTOMEDIA")
    if flags & IFF_DYNAMIC:
        readable_flags.append("DYNAMIC")

    return f"{flags:#04x}({','.join(readable_flags)})"

def interpret_ipv6_scope(scope_id):
    """
    Interpret the 32-bit scope ID to classify the IPv6 address.
    """
    # Direct comparisons based on known values after byte-order conversion
    if scope_id == 0x2000000:
        return "link-local"
    elif scope_id == 0x0000000:
        return "global"
    elif scope_id == 0x20000:
        return "node-local"
    elif scope_id == 0x80000:
        return "organization-local"
    elif scope_id == 0x100000:
        return "site-local"
    else:
        return "unknown"

def sockaddr_to_ip(sockaddr_ptr) -> Optional[str]:
    if not sockaddr_ptr:
        return None
    family = sockaddr_ptr.contents.sa_family
    if family == socket.AF_INET:
        ipv4 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in))
        ip = str(ipaddress.IPv4Address(bytes(ipv4.contents.sin_addr)))
        return ip
    elif family == socket.AF_INET6:
        ipv6 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in6))
        ip = str(ipaddress.IPv6Address(bytes(ipv6.contents.sin6_addr)))
        return ip
    return None

def sockaddr_to_prefixlen(sockaddr_ptr):
    """
    Convert an IPv6 netmask to its prefix length.
    """
    if sockaddr_ptr:
        family = sockaddr_ptr.contents.sa_family
        if family == socket.AF_INET6:
            # Cast to sockaddr_in6 and extract the netmask bytes
            ipv6_netmask = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in6))
            netmask_bytes = bytearray(ipv6_netmask.contents.sin6_addr)

            # Convert the netmask bytes directly to binary string and count the 1's
            binary_netmask = ''.join(format(byte, '08b') for byte in netmask_bytes)
            return binary_netmask.count('1')

    return None

def sockaddr_to_scope(sockaddr_ptr):
    """
    Extract and correctly interpret the 32-bit scope ID from an IPv6 address.
    """
    if sockaddr_ptr:
        family = sockaddr_ptr.contents.sa_family
        if family == socket.AF_INET6:
            # Cast to sockaddr_in6 and extract the scope ID, converting with ntohl
            ipv6_addr = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in6))
            raw_scope_id = ipv6_addr.contents.sin6_scope_id

            # Use ntohl to adjust byte order of the 32-bit scope ID
            scope_id = socket.ntohl(raw_scope_id)
            return scope_id
    return None

def get_mac_address(interface: str) -> Optional[str]:
    addr = ctypes.POINTER(ifaddrs)()
    if libc.getifaddrs(ctypes.byref(addr)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

    mac_address = None
    current = addr
    while current:
        iface_name = current.contents.ifa_name.decode('utf-8')
        if iface_name == interface:
            # print(f"DEBUG: Processing interface '{iface_name}'")
            if current.contents.ifa_addr and current.contents.ifa_addr.contents.sa_family == 17:  # 17 is AF_PACKET
                sockaddr_ll_ptr = ctypes.cast(current.contents.ifa_addr, ctypes.POINTER(sockaddr_ll))
                mac_address = ':'.join(format(b, '02x') for b in sockaddr_ll_ptr.contents.sll_addr[:6])
                # print(f"DEBUG: Extracted MAC: {mac_address}")
                break
        current = current.contents.ifa_next
    libc.freeifaddrs(addr)
    return mac_address

class Interface:
    """
    Class to store and initialize system interface attributes.
    """
    interface_name = None
    mac            = None
    ip             = None
    ipv6           = None
    gateway        = None
    mtu            = None
    inet_v4        = {}
    inet_v6        = {}
    flags          = None
    broadcast_mac  = 'ff:ff:ff:ff:ff:ff'

    def __init__(self, name: str):
        self.interface_name = name
        if not self.interface_name:  # This for read file mode
            self.mac           = ""
            self.ip            = ""
            self.ipv6          = ""
            self.gateway       = ""
            self.mtu           = ""
            self.inet_v4       = ""
            self.inet_v6       = ""
            self.flags         = ""
            self.broadcast_mac = ""
            return
        self.get_own_addresses()
        self.get_mtu()
        self.gateway = self.get_gateway()
        self.flags = get_interface_flags(self.interface_name)

    @staticmethod
    def is_temporary_ipv6(ipv6: str) -> bool:
        """
        Check if an IPv6 address is temporary based on the format.
        Temporary IPv6 addresses often have 'privacy extensions' and may include specific patterns.
        """
        try:
            ipv6_obj = ipaddress.IPv6Address(ipv6)
            return ipv6_obj.is_private or ipv6_obj.teredo
        except ValueError:
            return False

    def get_own_addresses(self):
        """
        Method to retrieve layer 2 and 3 addressing from specified interface.
        """
        try:
            self.mac = get_mac_address(self.interface_name)

            addr = ctypes.POINTER(ifaddrs)()
            if libc.getifaddrs(ctypes.byref(addr)) != 0:
                raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            
            current = addr
            eth_bcast_accessed = False
            while current:
                iface_name = current.contents.ifa_name.decode('utf-8')
                if iface_name == self.interface_name:

                    # Retrieve the Ethernet (MAC) broadcast address if available
                    if current.contents.ifa_addr and not eth_bcast_accessed:
                        # Cast to sockaddr_ll to read the broadcast MAC address
                        sockaddr_ll_ptr = ctypes.cast(current.contents.ifa_broadaddr, ctypes.POINTER(sockaddr_ll))
                        mac_broadcast = ':'.join(f'{b:02x}' for b in sockaddr_ll_ptr.contents.sll_addr[:6])
                        if mac_broadcast:
                            eth_bcast_accessed = True
                            self.broadcast_mac = mac_broadcast

                    ip_addr = sockaddr_to_ip(current.contents.ifa_addr)
                    if ip_addr:
                        if ':' in ip_addr:
                            # Classify IPv6 addresses
                            scope_id = sockaddr_to_scope(current.contents.ifa_addr)
                            ipv6_type = interpret_ipv6_scope(scope_id)
                            
                            self.inet_v6[ip_addr] = {"prefixlen": None, "scopeid": ipv6_type}
                            self.inet_v6[ip_addr]["scopeid"] = ipv6_type
                            # Retrieve the IPv6 prefix length
                            if current.contents.ifa_netmask and current.contents.ifa_addr.contents.sa_family == socket.AF_INET6:
                                prefixlen = sockaddr_to_prefixlen(current.contents.ifa_netmask)
                                if prefixlen:
                                    self.inet_v6[ip_addr]["prefixlen"] = prefixlen
                        else:
                            self.inet_v4[ip_addr] = {"netmask": None, "broadcast": None}

                            # Retrieve netmask if available (for IPv4)
                            if current.contents.ifa_netmask and current.contents.ifa_addr.contents.sa_family == socket.AF_INET:
                                netmask = sockaddr_to_ip(current.contents.ifa_netmask)
                                if netmask:
                                    self.inet_v4[ip_addr]["netmask"] = netmask
                                    #self.inet_v4[ip_addr]["broadcast"] = self.get_broadcast_address(self.interface_name)
                            
                            if current.contents.ifa_broadaddr:
                                bcast_addr = sockaddr_to_ip(current.contents.ifa_broadaddr)
                                if bcast_addr:
                                    self.inet_v4[ip_addr]["broadcast"] = bcast_addr

                current = current.contents.ifa_next
            libc.freeifaddrs(addr)

        except OSError as e:
            print(f'[!] System call error: {e}')
        except Exception as e:
            print(f'[!] ERROR: Please check the interface name and try again. ({e})')

    def get_gateway(self) -> Optional[str]:
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines():
                    parts = line.strip().split()
                    if parts[1] != '00000000' or not int(parts[3], 16) & 2:
                        continue
                    return socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
        except Exception as e:
            return ""

    def get_mtu(self):
        # Retrieve MTU by reading directly from /sys/class/net/<interface>/mtu
        try:
            with open(f"/sys/class/net/{self.interface_name}/mtu") as mtu_file:
                self.mtu = int(mtu_file.read().strip())
        except Exception as e:
           pass
        
    def __str__(self):
        print(f"{self.interface_name}: flags={self.flags} mtu {self.mtu}")
        for addr, vals in self.inet_v4.items():
            print(f"       inet {addr} netmask {vals['netmask']} broadcast {vals['broadcast']}")
        for addr, vals in self.inet_v6.items():
            print(f"       inet6 {addr} prefixlen {vals['prefixlen']} {vals['scopeid']}")
        print(f"       ether {self.mac} broadcast {self.broadcast_mac}")
        print(f'       gateway {self.gateway}')
        return ""

