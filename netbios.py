#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import List
from io import BytesIO
import struct
import socket

@dataclass
class NetBIOSNameRecord:
    name: str
    type_: int
    class_: int
    ttl: int
    data_length: int
    flags: int
    address: str

@dataclass
class NetBIOSResponse:
    transaction_id: int
    flags: int
    questions: int
    answers: int
    name_records: List[NetBIOSNameRecord] = field(default_factory=list)

def parse_netbios_response(data: bytes) -> NetBIOSResponse:
    # Use BytesIO for easier handling of byte streams
    reader = BytesIO(data)

    # Read and parse the NetBIOS response header
    header = reader.read(12)
    transaction_id, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', header)

    # Initialize the list to hold the name records
    name_records = []

    # Skip the question section if present (assuming questions count is 1 for simplicity)
    if questions > 0:
        reader.read(34)  # Skipping the question entry (34 bytes is a common size)

    # Parse each answer in the answer section
    for _ in range(answers):
        # Example parsing for a name record (adjust according to your specific needs)
        name = reader.read(34).decode('ascii').strip()  # Adjust the size and decoding as necessary
        type_, class_, ttl, data_length = struct.unpack('!HHIH', reader.read(10))
        flags = struct.unpack('!H', reader.read(2))[0]
        address = socket.inet_ntoa(reader.read(4))  # Assuming IPv4 address

        # Add the name record to the list
        name_records.append(NetBIOSNameRecord(name, type_, class_, ttl, data_length, flags, address))

    # Create and return the NetBIOSResponse object
    return NetBIOSResponse(transaction_id, flags, questions, answers, name_records)
