#!/usr/bin/env python3

import struct
import socket
from io import BytesIO
from typing import List
from dataclasses import dataclass, field


ECHO_PING_REQUEST = 128
ROUTER_SOLICITATION = 133
NEIGHBOR_SOLICITATION = 135
NEIGHBOR_ADVERTISEMENT = 136
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

def parse_icmp(data: bytes) -> ICMP | None:
    """
    Function to parse ICMP packets.
    """
    reader = BytesIO(data)
    icmp_header = reader.read(12)
    if len(icmp_header) < 12:
        return None
    type_, code, checksum, id, seq, timestamp = struct.unpack('!BBHHHI', icmp_header)

    return ICMP(type_, code, checksum, id, seq, timestamp)

def parse_icmpv6(reader: BytesIO) -> ICMPv6MulticastListenerReport | ICMPv6EchoReq | None:
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
