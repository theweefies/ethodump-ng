#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import List
from io import BytesIO
import struct
import socket

from globals import Client

QUERY = 0
ANSWER = 1

SERVER_SERVICE = '<20>'
MASTER_BROWSER = '<1b>'
DOMAIN_CONTROLLER = '<1c>'

@dataclass
class NetBIOSQuery:
    name: str
    type_: int
    class_: int

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


@dataclass
class NBNSHeader:
    id: int
    flags: int
    message_type: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class NBNSPacket:
    header: NBNSHeader
    questions: list
    answers: list
    authorities: list
    additionals: list

def format_and_clean_netbios_name(name: str) -> tuple[str, str]:
    """
    Function to format and clean netbios names.
    """
    # Check if the last character is a control character or non-printable
    if name and (ord(name[-1]) < 0x21 or ord(name[-1]) > 0x7E):
        # Convert the last character to its hex representation, e.g., <1b>
        control_char_formatted = f'<{ord(name[-1]):02x}>'
        # Remove the control character from the name and strip trailing whitespace
        cleaned_name = name[:-1].rstrip()
    else:
        control_char_formatted = ''
        cleaned_name = name.rstrip()

    # Append formatted control character if it was found
    return cleaned_name, control_char_formatted

def decode_netbios_name(encoded_name: bytes) -> None | tuple[str,str]:
    """
    Decode a NetBIOS name from its 'half-ASCII' encoding.
    """
    decoded_name = ''

    # Ensure that the encoded name is exactly 32 characters
    if len(encoded_name) != 32:
        return None

    # Process each encoded byte pair
    for i in range(0, 32, 2):  # 32 characters total, in steps of 2
        encoded_byte = encoded_name[i:i+2]
        # Debugging: Print the encoded byte pair being processed
        # print(f"Processing encoded byte pair: {encoded_byte}")
        # Convert each pair of characters back to a byte
        decoded_char = chr(((ord(encoded_byte[0]) - ord('A')) << 4) | (ord(encoded_byte[1]) - ord('A')))
        decoded_name += decoded_char

    # This regex matches any character that is not a printable ASCII char excluding space (0x20-0x7E)
    cleaned_name, control_code = format_and_clean_netbios_name(decoded_name)
    # NetBIOS names are space-padded to 16 chars, so strip trailing spaces
    return cleaned_name, control_code

def parse_netbios_record(reader: BytesIO, cur_client: Client, record_type: int=None) -> None | NetBIOSNameRecord | NetBIOSQuery:
    """
    Function to parse a netbios record.
    """
    # Example parsing for a name record (adjust according to your specific needs)
    name = reader.read(34)
    if len(name) < 34:
        return None

    encoded_name = name.decode('ascii').strip()[:32]
    decoded_name, control_code = decode_netbios_name(encoded_name)
    # print('\nDecoded name:', decoded_name)
    # print('Control code:', control_code)

    if record_type == QUERY:
        if control_code == SERVER_SERVICE or control_code == MASTER_BROWSER:
            cur_client.connections.add(decoded_name)
        elif control_code == DOMAIN_CONTROLLER:
            cur_client.hostnames.add(decoded_name)
        record_contents = reader.read(4)
        type_, class_ = struct.unpack('!HH', record_contents)
        return NetBIOSQuery(decoded_name, type_, class_)
    else:
        cur_client.hostnames.add(decoded_name)
        record_contents = reader.read(12)
        type_, class_, ttl, data_length, flags = struct.unpack('!HHIHH', record_contents)
        address = socket.inet_ntoa(reader.read(4))  # Assuming IPv4 address
        return NetBIOSNameRecord(decoded_name, type_, class_, ttl, data_length, flags, address)

def parse_netbios_header(reader: BytesIO) -> NBNSHeader:
    """
    Function to parse a netbios packet header.
    """
    # Read and parse the NetBIOS response header
    header = reader.read(12)
    if len(header) < 12:
        return None
    
    transaction_id = header[:2]
    flags = header[2:4]
    message_type = struct.unpack('!H', flags)[0] & 0x8000
    questions, answers, authority, additional = struct.unpack('!HHHH', header[4:])

    return NBNSHeader(transaction_id, flags, message_type, questions, answers, authority, additional)

def parse_netbios_packet(data: bytes, cur_client: Client) -> None | NBNSPacket:
    """
    Function to parse and craft an NBNS dataclass.
    """
    reader = BytesIO(data)
    header = parse_netbios_header(reader)

    if not header:
        return None
    
    # Lets use list comprehensions with a conditional clause to exclude None values
    questions = [record for record in (parse_netbios_record(reader, cur_client, QUERY) for _ in range(header.num_questions)) if record is not None]
    answers = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_answers)) if record is not None]
    authorities = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_authorities)) if record is not None]
    additionals = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_additionals)) if record is not None]

    return NBNSPacket(header, questions, answers, authorities, additionals)
