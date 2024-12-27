#!/usr/bin/env python3

"""
RIP protocol module for ethodump-ng.
"""
import struct
import socket
from dataclasses import dataclass, field
from typing import List, Union, Optional

@dataclass
class RIPEntry:
    """
    A dataclass representing a single RIP route entry.
    """
    family: int
    tag: int
    ip_address: str
    subnet_mask: str
    next_hop: str
    metric: int

@dataclass
class RIPPacket:
    """
    Base class for RIP packets.
    """
    command: int
    version: int
    entries: List[RIPEntry] = field(default_factory=list)

def parse_rip_entry(data: bytes, version: int) -> Optional[RIPEntry]:
    """
    Parse a single RIP entry from the data.

    :param data: The raw bytes of the entry.
    :param version: The RIP version (1 or 2).
    :return: An RIPEntry object or None if parsing fails.
    """
    if len(data) < 20:
        return None

    family, tag, ip_raw, mask_raw, next_hop_raw, metric = struct.unpack('!HH4s4s4sI', data[:20])

    ip_address = socket.inet_ntoa(ip_raw)
    subnet_mask = socket.inet_ntoa(mask_raw) if version == 2 else '255.255.255.0'
    next_hop = socket.inet_ntoa(next_hop_raw) if version == 2 else '0.0.0.0'

    return RIPEntry(
        family=family,
        tag=tag,
        ip_address=ip_address,
        subnet_mask=subnet_mask,
        next_hop=next_hop,
        metric=metric
    )

def parse_rip_packet(data: bytes) -> Union[RIPPacket, None]:
    """
    Parse a RIP packet from raw bytes.

    :param data: The raw packet data.
    :return: A RIPPacket object or None if the packet is invalid.
    """
    if len(data) < 4:
        return None

    command, version = struct.unpack('!BB', data[:2])

    if version not in (1, 2):
        return None

    entries = []
    offset = 4  # Start after command, version, and must-be-zero bytes

    while offset + 20 <= len(data):
        entry = parse_rip_entry(data[offset:offset + 20], version)
        if not entry:
            break
        entries.append(entry)
        offset += 20

    return RIPPacket(command=command, version=version, entries=entries)
