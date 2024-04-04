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

IPV4_ANY_ADDRESS = '0.0.0.0'
IPV6_ANY_ADDRESS = '::'
ETH_ANY_ADDRESS = 'ff:ff:ff:ff:ff:ff'

clients = {}
oui_table = {}
oui_file = "oui.csv"

DARK_RED = '\x1b[31m'
DEFAULT = '\x1b[0m'

def bytes_to_mac(bytes: bytes) -> str:
    """
    Converts a bytes MAC to a colon delimited string.
    """
    return ':'.join('{:02x}'.format(b) for b in bytes)

def bytes_to_ip(bytes: bytes) -> str:
    """
    Converts a 4-byte sequence to an IPv4 string
    """
    return socket.inet_ntoa(bytes)

def bytes_to_ipv6(bytes: bytes) -> str:
    """
    Converts a 16-byte seqence to an IPv6 string
    """
    return socket.inet_ntop(socket.AF_INET6, bytes)

def debug_to_log(payload: bytes) -> None:
    """
    Function to log debug data to a log file
    """
    f_open = open('debug.log', 'ab')
    f_open.write(payload)
    f_open.close()

def is_utf8_decodable(val: bytes) -> str | bool:
    """
    Function to attempt utf decoding.
    """
    if not val:
        return False
    try:
        # Attempt to decode the client_id as UTF-8
        decoded = val.decode('utf-8','ignore')
        return decoded  # Decoding succeeded, so it's a UTF-8 string
    except UnicodeDecodeError:
        return False  # Decoding failed, so it's not a UTF-8 string

def clean_name(name: str) -> str:
    """
    Function to remove whitespace and non-printable chars from a string
    """
    # Remove leading and trailing whitespace
    cleaned = name.strip()

    # Use a regular expression to remove non-printable characters
    # This regex keeps only printable ASCII characters (space to ~)
    cleaned = re.sub(r'[^\x20-\x7E]', '', cleaned)

    return cleaned

class Flags:
    """
    A class to manage global flags, signals, and output
    control flags.
    """
    def __init__(self):
        self.lock = None
        self.exit_flag = False
        self.write_wait = True
        self.key_code = None
        self.client_count = 1
        self.paused = False
        self.paused_device_selected = None
        self.device_switch = False
        self.q_pressed = False
        self.debug_pwrite = False

class Client:
    """
    A class to manage client data.
    """
    def __init__(self, src_mac: str, client_ct: int):
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
            self.fingerprints = {"dhcp":None, "tcp":None}
            self.model_check_complete = False
            self.tls_ja3_classifications = set()
            self.tls_snis = set()
            self.count = 0
            get_manufacturer(self)

    def __str__(self):
        """
        Overrides the string method to provide attribute printing.
        """
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
            f"Resource URLs: \n" + '\n'.join(self.resource_urls),
            f"Protocols: {', '.join(self.protocols)}",
            ', '.join([f"{protocol.upper()} Fingerprint: {fingerprint if fingerprint else 'Not Available'}" for protocol, fingerprint in self.fingerprints.items()]),
            f"TLS JA3 Classifications: {'; '.join(self.tls_ja3_classifications)}",
            f"TLS SNIs: {', '.join(self.tls_snis)}",
            f"Count: {self.count}"
        ]
        # Join all the attribute strings with newlines for pretty printing
        return "\n".join(attributes)

    def to_dict(self) -> dict:
        """
        Converts the class to a dictionary
        """
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

def get_manufacturer(self: Client) -> None:
    """
    Function to get do OUI -> Manufacture resolution for the Client class.
    """
    if self.src_mac:
        self.oui = self.src_mac.replace(':', '')[:6]
        if self.oui in oui_table:
            self.manufacturer = oui_table[self.oui].replace('"','')
        else:
            self.manufacturer = 'Unknown'
