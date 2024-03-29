#!/usr/bin/env python3
"""
DHCP Module for ethodump-ng.
"""
from dataclasses import dataclass, field
from typing import List, Tuple
from io import BytesIO
import struct
import socket

from globals import bytes_to_mac

DHCP_HNAME_OPT      = 12
DHCP_VCLASS_OPT     = 60
DHCP_CLIENTID_OPT   = 61
DHCP_DOMAINNAME_OPT = 15

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

# Example function to parse DHCPv6 options from the packet payload
def parse_dhcpv6_options(payload: bytes) -> List[Tuple[int, bytes]]:
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

def is_utf8_decodable(val):
    if not val:
        return False
    try:
        # Attempt to decode the client_id as UTF-8
        decoded = val.decode('utf-8','ignore')
        return decoded  # Decoding succeeded, so it's a UTF-8 string
    except UnicodeDecodeError:
        return False  # Decoding failed, so it's not a UTF-8 string

# Example of parsing a DHCPv6 packet and its options
def parse_dhcpv6_packet(data: bytes) -> DHCPv6Packet:
    reader = BytesIO(data)
    
    # Read the DHCPv6 packet header fields
    header = reader.read(4)
    message_type = header[0]
    transaction_id = header[1:4]

    # Parse options from the remaining payload
    options = parse_dhcpv6_options(reader.read())
    
    return DHCPv6Packet(message_type, transaction_id, options)

def extract_dhcp_client_details(dhcp_packet, cur_client):
    hostname = get_dhcp_option(dhcp_packet, DHCP_HNAME_OPT)
    hostname_decoded = is_utf8_decodable(hostname)
    if hostname_decoded:
        cur_client.hostnames.add(hostname_decoded)
    vendor_class = get_dhcp_option(dhcp_packet, DHCP_VCLASS_OPT)
    if is_utf8_decodable(vendor_class) and not cur_client.vendor_class:
        cur_client.vendor_class = is_utf8_decodable(vendor_class)
        cur_client.oses.add(cur_client.vendor_class)
    client_id = get_dhcp_option(dhcp_packet, DHCP_CLIENTID_OPT)
    client_id_decoded = is_utf8_decodable(client_id)
    if client_id_decoded:
        cur_client.hostnames.add(client_id_decoded)
    
def get_dhcp_option(dhcp_packet, option_code):
    """Retrieve a DHCP option value by its code from a DHCPPacket."""
    for code, data in dhcp_packet.options:
        if code == option_code:
            return data
    return None  # Return None if the option is not found

def parse_dhcp_packet(data):
    reader = BytesIO(data)
    header = reader.read(240)
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
