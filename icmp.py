#!/usr/bin/env python3

import os
import time
import struct
import socket
from io import BytesIO
from typing import List
from dataclasses import dataclass, field

from globals import DARK_RED, Client

ECHO_PING_REQUEST         = 128
ROUTER_SOLICITATION       = 133
ROUTER_ADVERTISEMENT      = 134
NEIGHBOR_SOLICITATION     = 135
NEIGHBOR_ADVERTISEMENT    = 136
MULTICAST_LIST_REP_MSG_V2 = 143

@dataclass
class ICMP:
    type_: int
    code: int
    checksum: int
    id: int
    seq: int
    timestamp: float

@dataclass
class MulticastOption:
    type_: int
    data: bytes

@dataclass
class MulticastAddressRecord:
    record_type: int
    aux_data_len: int
    num_sources: int
    multicast_address: str

@dataclass
class ICMPv6MulticastListenerReport:
    type_: int
    code: int
    checksum: int
    reserved: int
    num_multicast_address_records: int
    multicast_address_records: List[MulticastAddressRecord] = field(default_factory=list)

@dataclass
class ICMPv6NeighborSolicitation:
    type_: int
    code: int
    checksum: int
    reserved: int
    target: str
    options: List[MulticastOption] = field(default_factory=list)

@dataclass
class ICMPv6RouterSolicitation:
    type_: int
    code: int
    checksum: int
    reserved: int
    options: List[MulticastOption] = field(default_factory=list)

@dataclass
class ICMPv6RouterAdvertisement:
    type_: int
    code: int
    checksum: int
    cur_hop_limit: int
    flags: bytes
    router_lifetime: int
    reachable_time: int
    retrans_timer: int
    options: List[MulticastOption] = field(default_factory=list)

@dataclass
class ICMPv6EchoReq:
    type_: int
    code: int
    checksum: int
    id: int
    seq: int

@dataclass
class ICMPv6NeighborAdvertisement:
    type_: int
    code: int
    checksum: int
    flags: int
    target: str

def process_icmpv6_packet(packet, cur_client) -> None:
    if packet.type_ == ROUTER_ADVERTISEMENT:
        cur_client.ttl = packet.cur_hop_limit
        cur_client.color = DARK_RED

def parse_icmp(data: bytes) -> ICMP:
    """
    Function to parse ICMP packets.
    """
    reader = BytesIO(data)
    icmp_header = reader.read(12)
    if len(icmp_header) < 12:
        return None
    type_, code, checksum, id, seq, timestamp = struct.unpack('!BBHHHI', icmp_header)

    return ICMP(type_, code, checksum, id, seq, timestamp)

def parse_icmpv6(reader: BytesIO):
    """
    Function to parse ICMPv6 packets.
    """
    # Read the ICMPv6 header fields
    icmpv6_header = reader.read(4)
    if len(icmpv6_header) < 4:
        return None
    
    type_, code, checksum = struct.unpack('!BBH', icmpv6_header)
    
    if type_ == ECHO_PING_REQUEST:
        data = reader.read(4)
        if len(data) < 4:
            return None
        id, seq = struct.unpack('!HH', data)

        return ICMPv6EchoReq(type_, code, checksum, id, seq)

    elif type_ == NEIGHBOR_SOLICITATION:
        data = reader.read(4)
        if len(data) < 4:
            return None
        reserved = struct.unpack('!I', data)[0]

        data = reader.read(16)
        if len(data) < 16:
            return None
        target_address = socket.inet_ntop(socket.AF_INET6, data)
        
        options = []
        option_data = reader.read()
        while len(option_data) > 0:
            option_type = option_data[0]
            if len(option_data) < 2:
                break
            option_len = (option_data[1] * 8) # each increment == 8 bytes
            if len(option_data) < option_len:
                break
            option_val = option_data[2:option_len]
            options.append(MulticastOption(option_type, option_val))
            option_data = option_data[option_len:]

        return ICMPv6NeighborSolicitation(type_, code, checksum, reserved, target_address, options) 

    elif type_ == ROUTER_ADVERTISEMENT:
        data = reader.read(2)
        if len(data) < 2:
            return None
        cur_hop_limit = data[0]
        flags = data[1]

        data = reader.read(10)
        if len(data) < 10:
            return None
        router_lifetime, reachable_time, retrans_timer = struct.unpack('!HII', data)

        options = []
        option_data = reader.read()
        while len(option_data) > 0:
            option_type = option_data[0]
            if len(option_data) < 2:
                break
            option_len = (option_data[1] * 8) # each increment == 8 bytes
            if len(option_data) < option_len:
                break
            option_val = option_data[2:option_len]
            options.append(MulticastOption(option_type, option_val))
            option_data = option_data[option_len:]

        return ICMPv6RouterAdvertisement(type_, code, checksum, cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer, options)    
    
    elif type_ == ROUTER_SOLICITATION:
        data = reader.read(4)
        if len(data) < 4:
            return None
        reserved = struct.unpack('!I', data)[0]

        options = []
        option_data = reader.read()
        while len(option_data) > 0:
            option_type = option_data[0]
            if len(option_data) < 2:
                break
            option_len = (option_data[1] * 8) # each increment == 8 bytes
            if len(option_data) < option_len:
                break
            option_val = option_data[2:option_len]
            options.append(MulticastOption(option_type, option_val))
            option_data = option_data[option_len:]

        return ICMPv6RouterSolicitation(type_, code, checksum, reserved, options) 

    elif type_ == NEIGHBOR_ADVERTISEMENT:
        data = reader.read(4)
        if len(data) < 4:
            return None
        flags = struct.unpack('!I', data)[0]

        data = reader.read(16)
        if len(data) < 16:
            return None
        target_address = socket.inet_ntop(socket.AF_INET6, data)

        return ICMPv6NeighborAdvertisement(type_, code, checksum, flags, target_address)
    
    elif type_ == MULTICAST_LIST_REP_MSG_V2:
        data = reader.read(4)
        if len(data) < 4:
            return None
        reserved, num_multicast_address_records = struct.unpack('!HH', data)
        
        # Initialize the list to hold the multicast address records
        multicast_address_records = []

        # Parse each multicast address record
        for _ in range(num_multicast_address_records):
            record_header = reader.read(20)  # 2 bytes for record type, 1 byte for aux data len, 1 byte for num sources, and 4 bytes for multicast address
            if len(record_header) < 20:
                return None
            record_type, aux_data_len, num_sources = struct.unpack('!BBH', record_header[:4])
            multicast_address = socket.inet_ntop(socket.AF_INET6, record_header[4:])

            # Add the multicast address record to the list
            multicast_address_records.append(MulticastAddressRecord(record_type, aux_data_len, \
                                            num_sources, multicast_address))
        
        # Create and return the ICMPv6MLDv2Report object
        return ICMPv6MulticastListenerReport(type_, code, checksum, reserved, num_multicast_address_records, \
                    multicast_address_records)
    else:
        return None

def checksum(data: bytes) -> int:
    """Calculate the ICMP checksum."""
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def send_ping(client_obj: Client, status_info) -> None:
    """
    Send a single ping to the client
    """

    ICMP_ECHO_REQUEST = 8  # ICMP type for Echo Request
    ICMP_CODE         = 0
    # Use the process ID as the identifier
    ID                = os.getpid() & 0xFFFF
    SEQUENCE          = 1
    TIMEOUT           = 3

    destination_ip = client_obj.ip_address
    if not destination_ip:
        status_info.lower_status = "[!] IP Address not collected yet; can't send ping."
        return
    
    try:
        # Create a raw socket
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(TIMEOUT)

            # Construct the ICMP header and payload
            payload = b'Hello!'  # Example payload
            header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, ICMP_CODE, 0, ID, SEQUENCE)
            checksum_value = checksum(header + payload)
            header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, ICMP_CODE, checksum_value, ID, SEQUENCE)
            packet = header + payload

            # Send the packet
            send_time = time.time()
            sock.sendto(packet, (destination_ip, 0))

            # Wait for the reply
            response, addr = sock.recvfrom(1024)
            receive_time = time.time()

            # Unpack the ICMP header from the response
            icmp_header = response[20:28]
            icmp_type, icmp_code, _, reply_id, _ = struct.unpack('!BBHHH', icmp_header)

            if icmp_type == 0 and reply_id == ID:  # Echo Reply
                delay = (receive_time - send_time) * 1000  # Convert to ms
                status_info.lower_status = f"[+] Reply from {addr[0]}: time={delay:.2f}ms"
                return
            else:
                status_info.lower_status = "[!] Received an unexpected response."
                return
            
    except socket.timeout:
        status_info.lower_status = "[!] Request timed out."
        return
    except PermissionError:
        status_info.lower_status = "[!] Root privileges are required to send raw ICMP packets."
        return
    except Exception as e:
        status_info.lower_status = f"[!] An error occurred: {e}"
        return