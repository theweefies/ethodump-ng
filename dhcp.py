#!/usr/bin/env python3
"""
DHCP (& v6) Module for ethodump-ng.
"""
import struct
import socket

from io import BytesIO
from typing import List, Tuple
from dataclasses import dataclass, field

from globals import bytes_to_mac, clean_name, is_utf8_decodable, Client, DARK_RED
from models import dhcp_fingerprints

DHCP_HNAME_OPT      =  12
DHCP_VCLASS_OPT     =  60
DHCP_CLIENTID_OPT   =  61
DHCP_ROUTER_OPT     =   3
DHCP_DOM_NAME_OPT   =  15
DHCP_FQDN_OPT       = 119
DHCP_DNS_OPT        =   6
DHCP_SERVER_ID_OPT  =  54
DHCP_MESSAGE_TYPE   =  53

DHCP_DISCOVER = 1
DHCP_OFFER    = 2
DHCP_REQUEST =  3
DHCP_ACK =      5

DHCPV6_SOLICIT = 6 

DHCPV6_CLIENTID_OPT =  1
DHCPV6_FQDN_OPT     = 39

@dataclass
class DHCPPacket:
    message_type: int
    hardware_type: int
    hardware_address_length: int
    hops: int
    transaction_id: bytes
    seconds_elapsed: int
    bootp_flags: bytes
    client_ip: str
    your_ip: str
    next_server_ip: str
    relay_agent_ip: str
    client_mac: str
    magic_cookie: bytes
    options: List[Tuple[int, bytes]] = field(default_factory=list)

@dataclass
class DHCPv6Packet:
    message_type: int
    transaction_id: bytes
    options: List[Tuple[int, bytes]] = field(default_factory=list)  # Option code and option data

def match_dhcp_fingerprint(packet: DHCPPacket, cur_client: Client) -> None:
    """
    Function to match a current client's dhcp parameter list fingerprint
    against the database in models.py
    """
    global dhcp_fingerprints
    parameter_request_list = None

    # Step 1: Find Option 53 (Parameter Request List) and form the fingerprint string
    for option in packet.options:
        if option[0] == 55:  # DHCP Option Code 55 for Parameter Request List
            parameter_request_list = ','.join(str(param) for param in option[1])
            break

    if parameter_request_list:
        cur_client.fingerprints["dhcp"] = parameter_request_list
        
        # Step 2: Compare with Fingerprint Dictionary
        for fingerprint_key, fingerprint_value in dhcp_fingerprints.items():
            if parameter_request_list == fingerprint_value[1]:
                cur_client.oses.add('fp: ' + fingerprint_value[0])

def extract_dhcpv6_client_details(dhcpv6_packet: DHCPv6Packet, cur_client: Client) -> None:
    """
    Extract the Fully Qualified Domain Name (FQDN) from DHCPv6 options.
    """
    options = dhcpv6_packet.options
    msg_type = dhcpv6_packet.message_type

    for option_code, option_data in options:
        if option_code == DHCPV6_CLIENTID_OPT and msg_type == DHCPV6_SOLICIT:
            pass # could be useful for getting client mac in extender network situation
        elif option_code == DHCPV6_FQDN_OPT: # FQDN
            if len(option_data) < 1:
                return
            
            flags = option_data[0]
            domain_name_data = option_data[1:]  # Skip the first byte which is flags
            
            # Decode the domain name. Assume it's encoded in standard ASCII or UTF-8 for simplicity.
            domain_name = domain_name_data.decode('utf-8', 'ignore').strip()
            if domain_name:
                cur_client.hostnames.add(domain_name)

def parse_dhcpv6_options(payload: bytes) -> List[Tuple[int, bytes]]:
    """
    Function to parse DHCPv6 options from the dhcp payload
    """
    options = []
    reader = BytesIO(payload)
    
    while True:
        # Read the option code and length
        opt_hdr = reader.read(4)
        if len(opt_hdr) < 4:
            break  # End of options

        option_code, option_length = struct.unpack('!HH', opt_hdr)
        
        # Read the option data based on the length
        option_data = reader.read(option_length)
        options.append((option_code, option_data))

    return options

def parse_dhcpv6_packet(data: bytes) -> DHCPv6Packet:
    """
    Function to parse DHCPv6 packet.
    """
    reader = BytesIO(data)
    
    # Read the DHCPv6 packet header fields
    header = reader.read(4)
    message_type = header[0]
    transaction_id = header[1:4]

    # Parse options from the remaining payload
    options = parse_dhcpv6_options(reader.read())
    
    return DHCPv6Packet(message_type, transaction_id, options)

def extract_dhcp_client_details(dhcp_packet: DHCPPacket, cur_client: Client, clients: dict) -> None:
    """
    Function to attempt to extract hostname and vendor info
    from dhcp options
    """
    hostname = get_dhcp_option(dhcp_packet, DHCP_HNAME_OPT)
    hostname_decoded = is_utf8_decodable(hostname)
    if hostname_decoded and len(hostname_decoded) > 3:
        hostname_cleaned = clean_name(hostname_decoded)
        cur_client.hostnames.add(hostname_cleaned)

    vendor_class = get_dhcp_option(dhcp_packet, DHCP_VCLASS_OPT)
    if is_utf8_decodable(vendor_class) and not cur_client.vendor_class:
        cur_client.vendor_class = is_utf8_decodable(vendor_class)
        cur_client.oses.add('vc: ' + cur_client.vendor_class)

    """client_id = get_dhcp_option(dhcp_packet, DHCP_CLIENTID_OPT)
    client_id_decoded = is_utf8_decodable(client_id)
    if client_id_decoded and len(client_id_decoded) > 3:
        client_id_cleaned = clean_name(client_id_decoded)
        cur_client.hostnames.add(client_id_cleaned)"""

    dhcp_server_id = get_dhcp_option(dhcp_packet, DHCP_SERVER_ID_OPT)
    if dhcp_server_id:
        dhcp_server_ip = socket.inet_ntoa(dhcp_server_id)
        if dhcp_server_ip == cur_client.ip_address:
            cur_client.notes.add('dhcp_server')

    router = get_dhcp_option(dhcp_packet, DHCP_ROUTER_OPT)
    if router:
        router_ip = socket.inet_ntoa(router)
        if router_ip == cur_client.ip_address:
            cur_client.color = DARK_RED
            cur_client.notes.add('network_router')

    domain_name_server = get_dhcp_option(dhcp_packet, DHCP_DNS_OPT)
    if domain_name_server:
        try:
            domain_name_server_ip = socket.inet_ntoa(domain_name_server)
            if domain_name_server_ip == cur_client.ip_address:
                cur_client.notes.add('provides_network_dns')
        except OSError:
            pass

    domain_name = get_dhcp_option(dhcp_packet, DHCP_DOM_NAME_OPT)
    if domain_name and is_utf8_decodable(domain_name):
        domain_name_decoded = is_utf8_decodable(domain_name)
        domain_name_cleaned = clean_name(domain_name_decoded)
        cur_client.hostnames.add(domain_name_cleaned)

    fqdn = get_dhcp_option(dhcp_packet, DHCP_FQDN_OPT)
    if fqdn and is_utf8_decodable(fqdn):
        fqdn_decoded = is_utf8_decodable(fqdn)
        fqdn_cleaned = clean_name(fqdn_decoded)
        cur_client.hostnames.add(fqdn_cleaned)

    opt_53_msg_type = get_dhcp_option(dhcp_packet, DHCP_MESSAGE_TYPE)

    if opt_53_msg_type and type(opt_53_msg_type) == bytes and len(opt_53_msg_type) == 1:
        opt_53_msg_type = struct.unpack('!B', opt_53_msg_type)[0]
        if opt_53_msg_type in [DHCP_DISCOVER,DHCP_REQUEST]:
            cur_client.src_mac = dhcp_packet.client_mac

        if opt_53_msg_type == DHCP_ACK:
            mac = None
            cl_object = None
            for src_mac, client_object in clients.items():
                if isinstance(client_object, dict):
                    for src_ip, ext_client_object in client_object.items():
                        if src_ip == '0.0.0.0' and ext_client_object.src_mac == dhcp_packet.client_mac:
                            mac = src_mac
                            cl_object = ext_client_object
                            break
                if mac and cl_object:
                    break
            if mac and cl_object:
                clients[mac][dhcp_packet.your_ip] = cl_object
                clients[mac][dhcp_packet.your_ip].ip_address = dhcp_packet.your_ip
                clients[mac].pop('0.0.0.0')
    
def get_dhcp_option(dhcp_packet: DHCPPacket, option_code: int) -> bytes:
    """
    Retrieve a DHCP option value by its code from a DHCPPacket.
    """
    for code, data in dhcp_packet.options:
        if code == option_code:
            return data

    return None  # Return None if the option is not found

def parse_dhcp_packet(data: bytes) -> DHCPPacket:
    """
    Function to parse a DHCP packet.
    """
    reader = BytesIO(data)
    header = reader.read(240)
    if len(header) < 240:
        return None
    message_type, hardware_type, hardware_address_length, \
        hops = struct.unpack('!BBBB', header[:4])
    tx_id = header[4:8]
    seconds_elapsed = struct.unpack('!H', header[8:10])[0]
    bootp_flags = header[10:12]
    client_ip = socket.inet_ntoa(header[12:16])
    your_ip = socket.inet_ntoa(header[16:20])
    next_server_ip = socket.inet_ntoa(header[20:24])
    relay_agent_ip = socket.inet_ntoa(header[24:28])
    client_mac = bytes_to_mac(header[28:34])
    magic_cookie = header[236:240]

    # Parse DHCP options
    options = []
    while True:
        option_code = reader.read(1)  # Read one byte for the option code
        if not option_code:
            break  # No more options
        option_code = ord(option_code)  # Convert byte to int

        if option_code == 255:  # End option
            break

        option_length = ord(reader.read(1))  # Read one byte for the length
        option_data = reader.read(option_length)  # Read the data based on the length

        options.append((option_code, option_data))

    # Create the DHCP packet object with the parsed data and options
    return DHCPPacket(
        message_type=message_type,
        hardware_type=hardware_type,
        hardware_address_length=hardware_address_length,
        hops=hops,
        transaction_id=tx_id,
        seconds_elapsed=seconds_elapsed,
        bootp_flags=bootp_flags,
        client_ip=client_ip,
        your_ip=your_ip,
        next_server_ip=next_server_ip,
        relay_agent_ip=relay_agent_ip,
        client_mac=client_mac,
        magic_cookie=magic_cookie,
        options=options
    )
