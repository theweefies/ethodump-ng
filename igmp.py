#!/usr/bin/env python3
"""
IGMP Module for ethodump-ng
"""
import struct
import socket

from typing import List
from dataclasses import dataclass, field

MEMBERSHIP_QUERY = 0x11
MEMBERSHIP_REPORT_V2 = 0x16
LEAVE_GROUP = 0x17
MEMBERSHIP_REPORT_V3 = 0x22

@dataclass
class IGMPQuery:
    type_: int
    max_response_time: int
    checksum: int
    multicast_address: str
    srsp_qrv: int
    qqic: int
    num_src: int

@dataclass
class IGMPLeaveGroup:
    type_: int
    max_response_time: int
    checksum: int
    multicast_address: str

@dataclass
class IGMPReportRecord:
    record_type: int
    aux_data_len: int
    num_sources: int
    multicast_address: str
    source_addresses: List[str] = field(default_factory=list)

@dataclass
class IGMPReport:
    type_: int
    checksum: int
    reserved: int
    num_group_records: int
    group_records: List[IGMPReportRecord] = field(default_factory=list)

def parse_igmp(payload: bytes) -> None | IGMPQuery | IGMPReport:
    """
    Function to parse IGMP packets.
    """
    if len(payload) < 8:
        return None
    
    type_ = payload[0]

    if type_ == MEMBERSHIP_QUERY:
        max_response_time = payload[1] // 10
        checksum = struct.unpack('!H', payload[2:4])[0]
        multicast_address = socket.inet_ntoa(payload[4:8])
        if len(payload) > 12:
            srsp_qrv = payload[8]
            qqic = payload[9]
            num_src = struct.unpack('!H', payload[10:12])[0]
        else:
            srsp_qrv = 0
            qqic = 0
            num_src = 0
        return IGMPQuery(type_, max_response_time, checksum, multicast_address, srsp_qrv, qqic, num_src)

    elif type_ == MEMBERSHIP_REPORT_V2:
        max_response_time = payload[1] // 10
        checksum = struct.unpack('!H', payload[2:4])[0]
        multicast_address = socket.inet_ntoa(payload[4:8])
        srsp_qrv = 0
        qqic = 0
        num_src = 0
        return IGMPQuery(type_, max_response_time, checksum, multicast_address, srsp_qrv, qqic, num_src)

    elif type_ == LEAVE_GROUP:
        max_response_time = payload[1] // 10
        checksum = struct.unpack('!H', payload[2:4])[0]
        multicast_address = socket.inet_ntoa(payload[4:8])
        return IGMPLeaveGroup(type_, max_response_time, checksum, multicast_address)

    elif type_ == MEMBERSHIP_REPORT_V3:
        checksum = struct.unpack('!H', payload[2:4])[0]
        reserved = struct.unpack('!H', payload[4:6])[0]
        num_group_records = struct.unpack('!H', payload[6:8])[0]
        group_records = []
        offset = 8
        for _ in range(num_group_records):
            record_type, aux_data_len, num_sources = struct.unpack('!BBH', payload[offset:offset+4])
            multicast_address = socket.inet_ntoa(payload[offset+4:offset+8])
            source_addresses = [socket.inet_ntoa(payload[offset+8+(i*4):offset+12+(i*4)]) for i in range(num_sources)]
            offset += 8 + (num_sources * 4) + (aux_data_len * 4)
            group_records.append(IGMPReportRecord(record_type, aux_data_len, num_sources, multicast_address, source_addresses))
        return IGMPReport(type_, checksum, reserved, num_group_records, group_records)

    else:
        return None
