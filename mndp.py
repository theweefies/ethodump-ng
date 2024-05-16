#!/usr/bin/env python3
"""
MNDP module for ethodump-ng
"""

import struct
import socket

from io import BytesIO
from dataclasses import dataclass

from globals import Client, bytes_to_mac, bytes_to_ip

TLV_1_MAC_ADDRESS     = 1
TLV_5_IDENTITY        = 5
TLV_7_VERSION         = 7
TLV_8_PLATFORM        = 8
TLV_10_UPTIME         = 10
TLV_11_SOFTWARE_ID    = 11
TLV_12_BOARD          = 12
TLV_14_UNPACK         = 14
TLV_16_INTERFACE_NAME = 16
TLV_17_IPV4_ADDRESS   = 17

@dataclass
class MNDPPacket:
    header: bytes
    seqno: int
    tlvs: list

def parse_mndp_packet(data: bytes) -> (MNDPPacket | None):

    reader = BytesIO(data)
    tlvs = []

    header = reader.read(2)
    if len(header) < 2:
        return None
    
    seqno_data = reader.read(2)
    if len(seqno_data) < 2:
        return None
    seqno = struct.unpack('!H', seqno_data)[0]

    # Read the TLVs
    while reader.tell() < len(data):
        # Read and validate the type field
        t = reader.read(2)
        if len(t) < 2:
            return None
        t = struct.unpack('!H', t)[0]

        # Read and validate the length field
        l = reader.read(2)
        if len(l) < 2:
            return None
        l = struct.unpack('!H', l)[0]

        # Read and validate the value field
        v = reader.read(l)
        if len(v) < l:
            return None

        # Append the TLV to the list
        tlvs.append((t, l, v))

    return MNDPPacket(header, seqno, tlvs)

def process_mndp_packet(packet: MNDPPacket, cur_client: Client) -> None:
    for t,_,v in packet.tlvs:
        if t == TLV_1_MAC_ADDRESS:
            if not cur_client.src_mac:
                cur_client.src_mac = bytes_to_mac(v)
        elif t == TLV_5_IDENTITY:
            cur_client.hostnames.add(v.decode('utf-8', 'ignore'))
        elif t == TLV_7_VERSION:
            cur_client.oses.add(v.decode('utf-8', 'ignore'))
        elif t == TLV_8_PLATFORM:
            cur_client.oses.add(v.decode('utf-8', 'ignore'))
        elif t == TLV_11_SOFTWARE_ID:
            cur_client.oses.add(v.decode('utf-8', 'ignore'))
        elif t == TLV_12_BOARD:
            cur_client.oses.add(v.decode('utf-8', 'ignore'))
        elif t == TLV_17_IPV4_ADDRESS:
            if not cur_client.ip_address:
                cur_client.ip_address = bytes_to_ip(v)
