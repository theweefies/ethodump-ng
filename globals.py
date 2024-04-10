#!/usr/bin/env python3

import socket
import re
import ipaddress
import os
import threading
import urllib.request
from urllib.parse import urlparse, ParseResult

ETH_P = b'\x08\x00'
ETH_IPV6 = b'\x86\xDD'
ARP_P = b'\x08\x06'
ETH_P_ALL = 0x0003

# Standard 80211 pcap global header (24 bytes)
PCAP_GLOBAL_HEADER_ETHERNET = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
MAGIC = 0xa1b2c3d4 # BE
CIGAM = 0xd4c3b2a1 # LE

GENERIC_UPNP_UA = 'Mozilla/5.0 (compatible; UPnP/1.1)'

QUEUE_SIZE = 1000

IPV4_ANY_ADDRESS = '0.0.0.0'
IPV6_ANY_ADDRESS = '::'
ETH_BCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'
ETH_ANY_ADDRESS = '00:00:00:00:00:00'

clients = {}
oui_table = {}
oui_file = "oui.csv"

DARK_RED = '\x1b[31m'
DEFAULT = '\x1b[0m'
CURSOR_TO_TOP = '\x1b[H'
CLEAR_SCREEN_CURSOR_TO_TOP = '\x1b[2J\x1b[H'

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
    if isinstance(val, str):
        return val
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

def is_private_ipv4(ip_str: str) -> bool:
    """
    Function to test if an ip address is private.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return True
        return False
    except ValueError:
        return False

class Flags:
    """
    A class to manage global flags, signals, output
    control flags, and thread locks.
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
            self.dns_names = set()
            self.protocols = set()
            self.fingerprints = {"dhcp":None, "tcp":None}
            self.model_check_complete = False
            self.tls_ja3_classifications = set()
            self.tls_snis = set()
            self.cred_pairs = set()
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
            f"Resource URLs: {', '.join(self.resource_urls)}",
            f"DNS Queries: {', '.join(self.dns_names)}",
            f"Protocols: {', '.join(self.protocols)}",
            ', '.join([f"{protocol.upper()} Fingerprint: {fingerprint if fingerprint else 'Not Available'}" for protocol, fingerprint in self.fingerprints.items()]),
            f"TLS JA3 Classifications: {'; '.join(self.tls_ja3_classifications)}",
            f"TLS SNIs: {', '.join(self.tls_snis)}",
            f"Credential Pairs: {', '.join(self.cred_pairs)}",
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

def add_port(src_port: int, cur_client: Client) -> None:
    """
    Function to add a port number to the client class instance.
    """
    if src_port < 5500:
        cur_client.ports.add(src_port)

def add_ttl(ttl: int, src_port: int, dst_port, cur_client: Client) -> None:
    """
    Function to add a ttl for known trustworthy port traffic
    Port/TTL relational analysis:
    tshark -r test.dump -Y "ip.src == $IP_ADDRESS" -Tfields -e ip.ttl -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport | sort -u

    DHCP, MDNS, and SSDP seem to have unreliable TTL values that do not reflect the device type.
    """
    if dst_port == 1900 or src_port == 1900:
        return
    elif dst_port == 5353 or src_port == 5353:
        return
    elif dst_port == 68 or src_port == 68:
        return
    
    cur_client.ttl = ttl

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

def check_make_path(dir: str, filename: str) -> str | None:
    """
    Function to check if a path exists; creates
    it if it does not. Returns the full path if 
    success, just the filename if creating the dir
    raises an OSError.
    """
    cwd = os.getcwd()
    new_full_path = os.path.join(cwd, dir)
    if not os.path.exists(new_full_path):        
        try:
            os.makedirs(new_full_path, mode=0o777, exist_ok=True)
        except OSError:
            return filename

    return os.path.join(new_full_path, filename)

def grab_resource(urn: str, user_agent: str, parsed_urn: ParseResult, lock: threading.Lock):
    """
    Fetches a resource from the specified URN using a custom User-Agent and saves it to a file.

    :param urn: The Uniform Resource Name (e.g., a URL) of the resource to fetch.
    :param user_agent: The custom User-Agent string to use for the request.
    :param filename: The name of the file where the resource will be saved.
    """
    with lock:
        # Create a request object with the custom User-Agent
        req = urllib.request.Request(urn, headers={'User-Agent': user_agent})

        # Perform the request
        with urllib.request.urlopen(req) as response:
            # Read the response
            content = response.read()
            if content:
                dir_name = parsed_urn.hostname
                filename = parsed_urn.path.strip('/')
                abs_path = check_make_path(dir_name, filename)
                
                # Save the content to a file
                with open(abs_path, 'wb') as f:
                    f.write(content)