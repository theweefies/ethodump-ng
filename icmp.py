#!/usr/bin/env python3

import struct
import socket

from typing import List
from dataclasses import dataclass, field

@dataclass
class ICMP:
    type_: int
    code: int
    checksum: bytes
    id: int
    seq: int
    timestamp: float

@dataclass
class MulticastAddressRecord:
    record_type: int
    aux_data_len: int
    num_sources: int
    multicast_address: str

@dataclass
class ICMPv6:
    type_: int
    code: int
    checksum: bytes
    reserved: bytes
    num_multicast_address_records: int
    multicast_address_records: List[MulticastAddressRecord] = field(default_factory=list)

def parse_icmp(reader) -> ICMP:
    icmp_header = reader.read(10)
    if len(icmp_header) < 10:
        return None
    type_, code, checksum, id, seq, timestamp = struct.unpack('!BBHHI', icmp_header)
    
    return ICMP(type_, code, checksum, id, seq, timestamp)

def parse_icmpv6(reader) -> ICMPv6:
    # Read the ICMPv6 header fields
    icmpv6_header = reader.read(8)
    if len(icmpv6_header) < 8:
        return None
    
    type_, code = struct.unpack('!BB', icmpv6_header[:2])
    checksum = icmpv6_header[2:4]
    reserved = icmpv6_header[4:6]
    num_multicast_address_records = struct.unpack('!H', icmpv6_header[6:8])[0]
    
    # Initialize the list to hold the multicast address records
    multicast_address_records = []

    # Parse each multicast address record
    for _ in range(num_multicast_address_records):
        record_header = reader.read(20)  # 2 bytes for record type, 1 byte for aux data len, 1 byte for num sources, and 4 bytes for multicast address
        record_type, aux_data_len, num_sources = struct.unpack('!BBH', record_header[:4])
        multicast_address = socket.inet_ntop(socket.AF_INET6, record_header[4:])

        # Add the multicast address record to the list
        multicast_address_records.append(MulticastAddressRecord(record_type, aux_data_len, \
                                        num_sources, multicast_address))
    
    # Create and return the ICMPv6MLDv2Report object
    return ICMPv6(type_, code, checksum, reserved, num_multicast_address_records, \
                  multicast_address_records)