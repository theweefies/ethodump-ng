#!/usr/bin/env python3
"""
Globals module for ethodump-ng
"""
import re
import os
import sys
import yaml
import queue
import time
import uuid
import socket
import random
import ipaddress
import string
import base64
import hashlib
import subprocess
import urllib.request
from collections import Counter
from urllib.parse import urlparse, ParseResult
from urllib.error import URLError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import yaml.scanner

ETH_P        = b'\x08\x00'
ETH_IPV6     = b'\x86\xDD'
ARP_P        = b'\x08\x06'
REALTEK_L2_P = b'\x88\x99'

ETH_HEADER_LEN = 14
LLC_HEADER_LEN = 8

ETH_P_ALL    = 0x0003

# Standard 80211 pcap global header (24 bytes)
PCAP_GLOBAL_HEADER_ETHERNET = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
MAGIC = 0xa1b2c3d4 # BE
CIGAM = 0xd4c3b2a1 # LE

GENERIC_UPNP_UA = 'Mozilla/5.0 (compatible; UPnP/1.1)'

DHIP_HEADER = b'\x20\x00\x00\x00\x44\x48\x49\x50'

QUEUE_SIZE = 1000

IPV4_ANY_ADDRESS  = '0.0.0.0'
IPV6_ANY_ADDRESS  = '::'
ETH_BCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'
ETH_ANY_ADDRESS   = '00:00:00:00:00:00'
SPAN_TREE_ADDRESS = '01:80:c2:00:00:00'
CDP_MAC_ADDRESS   = '01:00:0c:cc:cc:cc'

clients = {}
oui_table = {}
oui_file = "oui.csv"
tcp_fp_dbase_list = []
tcp_fps = {}

http_queue = queue.Queue(1000)
mdns_queue = queue.Queue(100)
ssdp_queue = queue.Queue(100)

HOSTNAME = subprocess.getoutput('hostname')

DARK_RED = '\x1b[31m'
DEFAULT = '\x1b[0m'
CURSOR_TO_TOP = '\x1b[H'
CLEAR_SCREEN_CURSOR_TO_TOP = '\x1b[2J\x1b[H'

# Mapping keys to clients for display expansion
key_mapping = {'w': 10, 'e': 11, 'r': 12, 't': 13, 'y': 14, 'u': 15, 'i': 16, 'o': 17, 'p': 18, 'a': 19, 's':20}

def generate_random_mac():
    # Generate a random MAC address
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    # Format it as a colon-separated string
    mac_address = ':'.join(f'{octet:02x}' for octet in mac)
    return mac_address

def generate_sha1_hash(src_mac: str):
    sha1_hash = hashlib.sha1(src_mac.encode())
    sha1_hex = sha1_hash.hexdigest()
    
    return sha1_hex

def generate_hex_string(length):
    hex_digits = "0123456789abcdef"
    random.seed(time.time())
    
    hex_string = ''.join(random.choice(hex_digits) for _ in range(length))
    
    return hex_string

def generate_base32_id(length=26):
    random_bytes = os.urandom(length)
    base32_id = base64.b32encode(random_bytes).decode('utf-8').rstrip('=').lower()
    return base32_id[:length]

def generate_random_public_key():
    # Generate a random 8-byte string and encode it to Base64
    random_bytes = bytes(random.getrandbits(8) for _ in range(8))
    public_key = base64.b64encode(random_bytes).decode('utf-8')
    return public_key

def generate_random_version_code():
    # Generate random version code in the format: 2.9.0
    major = 2 #random.randint(1, 9)
    minor = random.randint(1, 9)
    patch = random.randint(1, 9)
    version_code = f"{major}.{minor}.{patch}"
    return version_code

def generate_random_model_name():
    # Generate random model name in the format: ls55cg970nnxgo
    model_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=14))
    return model_name

def generate_random_version_string():
    # Generate random version string in the format: 3.203.233-g11721767
    major = random.randint(1, 9)
    minor = random.randint(100, 999)
    patch = random.randint(100, 999)
    hash_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    version_string = f"{major}.{minor}.{patch}-g{hash_part}"
    return version_string

BASE32 = generate_base32_id()
RANDOM_MAC = generate_random_mac()
SHA1_HASH = generate_sha1_hash(RANDOM_MAC)
PK = generate_hex_string(64)
SHORT_PK = generate_random_public_key()
CID = generate_hex_string(32)
UUID_K = str(uuid.uuid4())
VERSION_TRIPLET = generate_random_version_code()
MODEL_NAME = generate_random_model_name()
LONG_VERSION = generate_random_version_string()
PRIVATE_KEY_RSA = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
PUBLIC_KEY_RSA = PRIVATE_KEY_RSA.public_key().public_bytes(
        encoding=serialization.Encoding.DER, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
PUBLIC_KEY_RSA_B64 = base64.b64encode(PUBLIC_KEY_RSA).decode('utf-8')

def is_self_L2(packet_mac: str, iface_mac: str) -> bool:
    """
    Function to compare the source mac of a packet with the
    current system interface mac. Used to ignore packet coming
    from the system interface.
    """
    if packet_mac == iface_mac:
        return True
    else:
        return False
    
def is_self_L2_L3(packet_mac: str, iface, packet_ip: str) -> bool:
    """
    Function to compare the source mac of a packet with the
    current system interface mac (and for layer 3 as well). 
    Used to ignore packet coming from the system interface.
    """
    if packet_mac == iface.mac and packet_ip == iface.ip:
        return True
    else:
        return False

def is_multicast_or_broadcast_ip(ip: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_multicast or ip == "255.255.255.255"
    except ValueError:
        return False

def is_multicast_or_broadcast(mac_address: str) -> bool:
    """
    Check if the MAC address is multicast or broadcast.
    """
    if mac_address == ETH_BCAST_ADDRESS:
        return True  # Broadcast address
    elif mac_address == SPAN_TREE_ADDRESS:
        return True

    # Split the MAC address string into octets and take the first one
    first_octet_str = mac_address.split(':')[0]  # Assuming MAC address is separated by ':'
    # Convert the first octet to an integer
    first_octet_int = int(first_octet_str, 16)  # Convert from hexadecimal to integer
    # Multicast address check (LSB of first octet is 1)
    return (first_octet_int & 0x01) == 0x01

def validate_ip(ip):
    """Validate an IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def validate_port(port):
    """Validate a port number."""
    return 0 < port <= 65535

class RedirectObject:
    def __init__(self, red_port, red_port_https, red_ip, tgt_ip, hostname, red_path, cert_file, key_file):
        self.redirect_port = red_port
        self.redirect_port_https = red_port_https
        self.redirect_ip = red_ip
        self.target_ip = tgt_ip
        self.hostname = hostname if hostname else HOSTNAME
        self.redirect_path = red_path
        self.cert_file = cert_file
        self.key_file = key_file

def load_redirect_yaml(file_path):
    if not os.path.exists(file_path):
        print('[!] ERROR: Configuration file does not exist.')
        sys.exit(0)
    try:
        print(f'[+] Loading yaml redirect config "{file_path}"')
        with open(file_path, 'r') as file:
            config = yaml.safe_load(file)
    except yaml.scanner.ScannerError as e:
        print('[!] ERROR: Malformed yaml configuration file.')
        sys.exit(0)

    redirect_port = config.get('Redirect-Port')
    redirect_port_https = config.get('Redirect-Port-HTTPS')
    redirect_https_cert = config.get('HTTPS-Cert')
    redirect_https_key = config.get('HTTPS-Key')
    redirect_ip = config.get('Redirect-IP')
    target_ip = config.get('Target-IP')
    hostname = config.get('Hostname')
    redirect_path = config.get('Redirect-Path')

    errors = []

    # Validate Redirect-Port
    if not isinstance(redirect_port, int) or not validate_port(redirect_port):
        errors.append(f"Invalid Redirect-Port: {redirect_port}")

    if redirect_port_https and (not isinstance(redirect_port_https, int) or not validate_port(redirect_port_https)):
        errors.append(f"Invalid Redirect-Port-HTTPS: {redirect_port_https}")

    if redirect_port_https:
        if not redirect_https_cert:
            errors.append(f"HTTPS/TLS Cert file missing from config.")
        elif not os.path.exists(redirect_https_cert):
            errors.append(f"HTTPS/TLS Cert file does not appear to exist.")
        if not redirect_https_key:
            errors.append(f"HTTPS/TLS Key file missing.")
        elif not os.path.exists(redirect_https_key):
            errors.append(f"HTTPS/TLS Key file does not appear to exist.")

    # Validate Redirect-IP
    if not validate_ip(redirect_ip):
        errors.append(f"Invalid Redirect-IP: {redirect_ip}")

    # Validate Target-IP
    if not validate_ip(target_ip):
        errors.append(f"Invalid Target-IP: {target_ip}")

    # Validate Hostname
    if hostname and not isinstance(hostname, str):
        errors.append(f"Invalid Hostname: {hostname}")

    # Validate Redirect-Path
    if not redirect_path or not isinstance(redirect_path, str):
        errors.append(f"Invalid Redirect-Path: {redirect_path}")

    if errors:
        print("    The following errors occurred in the configuration file:")
        for error in errors:
            print(f"[!] ERROR: {error}.")
        sys.exit(0)
    else:
        # Return the valid configuration
        return RedirectObject(redirect_port, redirect_port_https, redirect_ip,
                            target_ip, hostname, redirect_path, redirect_https_cert, redirect_https_key)

def mac_address_to_bytes(mac_address):
    """
    Convert a colon-delimited MAC address string to a byte string.
    """
    hex_str = mac_address.replace(':', '')
    return bytes.fromhex(hex_str)

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

class ResponseObject:
    """
    An object class to hold data required for response packets.
    """
    def __init__(self, type_ , unicast, hostname, src_mac, src_ip, src_ipv6, dst_mac, dst_ip, service, srv_port, srv_port_https):
        self.hostname = hostname
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.src_ipv6 = src_ipv6
        self.srv_port = srv_port if srv_port else 7000
        self.srv_port_https = srv_port_https
        self.service = service
        self.type_ = type_
        self.unicast = unicast
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip

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
        self.extender_present = False
        self.playback_speed = 1

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
            self.ttl_values = []
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
            self.color = None
            self.notes = set()
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
            f"Make/Model/OS: {', '.join(self.oses)}",
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
            f"Packet Count: {self.count}",
            f"Notes: {', '.join(self.notes)}"
        ]
        # Join all the attribute strings with newlines for pretty printing
        return "\n".join(attributes)

    def to_dict(self, show_ipv6) -> dict:
        """
        Converts the class to a dictionary
        """
        
        dict_data = {}

        dict_data['#']      = self.client_count
        dict_data['SOURCE'] = self.src_mac
        dict_data['IPv4']   = self.ip_address
        if show_ipv6:
            dict_data['IPv6'] = self.ipv6_address
        dict_data['MANUFACTURER'] = self.manufacturer
        dict_data['HOSTNAME']     = self.hostnames
        dict_data['SERVICES']     = self.services
        dict_data['TTL']          = self.ttl
        dict_data['MAKE/MODEL/OS']= self.oses
        dict_data['PORTS']        = self.ports
        dict_data['COUNTS']       = self.count 
    
        return dict_data

def add_port(dst_port: int, cur_client: Client) -> None:
    """
    Function to add a port number to the client class instance.
    """
    if dst_port < 40000:
        cur_client.ports.add(dst_port)

def add_ttl(ttl: int, cur_client: Client) -> None:
    """
    Function to add a ttl for known trustworthy port traffic
    Port/TTL relational analysis:
    tshark -r test.dump -Y "ip.src == $IP_ADDRESS" -Tfields -e ip.ttl -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport | sort -u
    """
    guessed_ttl_start = ttl

    if ttl < 0:
        return
    elif ttl >= 0 and ttl <= 32:
        guessed_ttl_start = 32
    elif ttl > 32 and ttl <= 64:
        guessed_ttl_start = 64
    elif ttl > 64 and ttl <= 128:
        guessed_ttl_start = 128
    elif ttl > 128:
        guessed_ttl_start = 255

    cur_client.ttl_values.append(guessed_ttl_start)

    if len(cur_client.ttl_values) > 2:
        ttl_counter = Counter(cur_client.ttl_values)
        most_common_ttl = ttl_counter.most_common(1)[0][0]
        average_ttl = most_common_ttl
    elif len(cur_client.ttl_values) == 2:
        average_ttl = min(cur_client.ttl_values)
    else:
        average_ttl = cur_client.ttl_values[0]

    cur_client.ttl = average_ttl


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

def grab_resource(urn: str, user_agent: str, parsed_urn: ParseResult):
    """
    Fetches a resource from the specified URN using a custom User-Agent and saves it to a file.

    :param urn: The Uniform Resource Name (e.g., a URL) of the resource to fetch.
    :param user_agent: The custom User-Agent string to use for the request.
    :param filename: The name of the file where the resource will be saved.
    """
    
    try:
        # Create a request object with the custom User-Agent
        req = urllib.request.Request(urn, headers={'User-Agent': user_agent})

        # Perform the request
        with urllib.request.urlopen(req) as response:
            # Read the response
            content = response.read()
            if content:
                dir_name = parsed_urn.hostname
                filename = parsed_urn.path.rstrip('/').split('/')[-1]
                abs_path = check_make_path(dir_name, filename)
                
                # Save the content to a file
                with open(abs_path, 'wb') as f:
                    f.write(content)
    
    except URLError:
        pass

def display_menu(options):
    """
    Displays a simple menu with options for the user to choose from.
    """
    
    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")
    print(f"0. Exit\n")

def get_user_selection(options):
    """
    Prompts the user to select an option from the menu.
    """
    while True:
        display_menu(options)
        try:
            choice = int(input("Select an option: "))
            if choice == 0:
                return None  # Exit option
            if 1 <= choice <= len(options):
                return options[choice - 1]
            else:
                print("[!] Invalid selection. Please try again.")
        except ValueError:
            print("[!] Please enter a valid number.")

def ethodump_select_addresses(available_ipv4, available_ipv6):
    """
    Prompts the user to select which IPv4 and IPv6 addresses to use.
    """
    if not available_ipv4:
        return None, None

    print("[?] IP Address Selection")
    print("    - Multiple Addresses have been detected. For active responses,")
    print("    - mDNS query responses, and mDNS redirection, you must choose")
    print("    - one address for IPv4. IPv6 is optional.\n")
    
    # Select IPv4 Address
    selected_ipv4 = None
    if available_ipv4:
        if len(available_ipv4) == 1:
            selected_ipv4 = available_ipv4[0]
        else:
            selected_ipv4 = get_user_selection(available_ipv4)
            if selected_ipv4:
                print(f"[+] Selected IPv4 Address: {selected_ipv4}")
                input("    Press enter to continue...")
            else:
                print('[!] You must choose an address or remove the redirect option.')
                exit()

    sys.stdout.write(CLEAR_SCREEN_CURSOR_TO_TOP)
    
    # Select IPv6 Address
    selected_ipv6 = None
    if available_ipv6:
        print("[?] IPv6 Address Selection:\n")
        if len(available_ipv6) == 1:
            selected_ipv6 = available_ipv6[0]
        else:
            selected_ipv6 = get_user_selection(available_ipv6)
            if selected_ipv6:
                print(f"[+] Selected IPv6 Address: {selected_ipv6}")
                input("    Press enter to continue...")
    
    return selected_ipv4, selected_ipv6

def detect_addresses(iface):
    """Function to determine if multiple addresses are available."""
    if not iface:
        return
    
    available_ipv4 = []
    available_ipv6 = []

    for ip in iface.inet_v4.keys():
        available_ipv4.append(ip)
    
    for ipv6 in iface.inet_v6.keys():
        available_ipv6.append(ipv6)

    return available_ipv4, available_ipv6