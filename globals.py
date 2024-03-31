#!/usr/bin/env python3

import socket
import re

ETH_P = b'\x08\x00'
ETH_IPV6 = b'\x86\xDD'
ARP_P = b'\x08\x06'
ETH_P_ALL = 0x0003

# Standard 80211 pcap global header (24 bytes)
PCAP_GLOBAL_HEADER_ETHERNET = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

QUEUE_SIZE = 1000

clients = {}
oui_table = {}
oui_file = "oui.csv"

def bytes_to_mac(bytes):
    """
    Converts a bytes MAC to a colon delimited string.
    """
    return ':'.join('{:02x}'.format(b) for b in bytes)

def bytes_to_ip(bytes):

    return socket.inet_ntoa(bytes)

def bytes_to_ipv6(bytes):

    return socket.inet_ntop(socket.AF_INET6, bytes)

def debug_to_log(payload):
    f_open = open('debug.log', 'ab')
    f_open.write(payload)
    f_open.close()

def get_manufacturer(self):
    if self.src_mac:
        self.oui = self.src_mac.replace(':', '')[:6]
        if self.oui in oui_table:
            self.manufacturer = oui_table[self.oui].replace('"','')
        else:
            self.manufacturer = 'Unknown'


def clean_name(name):
    # Remove leading and trailing whitespace
    cleaned = name.strip()

    # Use a regular expression to remove non-printable characters
    # This regex keeps only printable ASCII characters (space to ~)
    cleaned = re.sub(r'[^\x20-\x7E]', '', cleaned)

    return cleaned

class Client:
    def __init__(self, src_mac, client_ct):
            self.client_count = client_ct
            self.src_mac = src_mac
            self.ip_address = None
            self.ipv6_address = None
            self.oui = None
            self.manufacturer = None
            self.hostnames = set()
            self.vendor_class = None
            self.services = set()
            self.user_agents = set()
            self.oses = set()
            self.ttl = None
            self.ports = set()
            self.communicants = {}
            self.connections = set()
            self.resource_urls = set()
            self.protocols = set()
            self.count = 0
            get_manufacturer(self)

    def __str__(self):
        # Create a list of formatted strings for each attribute
        attributes = [
            "\n" + f"Client Count: {self.client_count}",
            f"Source MAC: {self.src_mac}",
            f"IP Address: {self.ip_address}",
            f"IPv6 Address: {self.ipv6_address}",
            f"OUI: {self.oui}",
            f"Manufacturer: {self.manufacturer}",
            f"Hostnames: {', '.join(self.hostnames)}",
            f"Vendor Class: {self.vendor_class}",
            f"Services: {', '.join(self.services)}",
            f"User Agents: {', '.join(self.user_agents)}",
            f"Operating Systems: {', '.join(self.oses)}",
            f"TTL: {self.ttl}",
            f"Ports: {', '.join(map(str, self.ports))}",
            f"Communicants: {', '.join(f'{k}: {v}' for k, v in self.communicants.items())}",
            f"Connections: {', '.join(self.connections)}",
            f"Resource URLs: \r\n" + '\r\n'.join(self.resource_urls),
            f"Protocols: {', '.join(self.protocols)}",
            f"Count: {self.count}"
        ]
        # Join all the attribute strings with newlines for pretty printing
        return "\n".join(attributes)

    def to_dict(self):
        return {
            '#': self.client_count,
            'SOURCE': self.src_mac,
            'IPv4': self.ip_address,
            'IPv6': self.ipv6_address,
            'MANUFACTURER': self.manufacturer,
            'HOSTNAME': self.hostnames,
            'SERVICES': self.services,
            'TTL': self.ttl,
            'OS': self.oses,
            'CONNECTIONS': self.connections,
            'PORTS': self.ports,
            'COUNTS': self.count
        }
