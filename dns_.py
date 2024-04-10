#!/usr/bin/env python3

"""
Module to handle DNS packets for ethodump-ng.
"""

from dataclasses import dataclass
from io import BytesIO
import socket
import struct

from globals import is_utf8_decodable, Client

DNS_HTTPS = 65
DNS_PTR = 12
DNS_TXT = 16
DNS_SRV = 33
DNS_A = 1
DNS_AAAA = 28
DNS_NSEC = 47
DNS_ANY = 255
DNS_OPT = 41
DNS_CNAME = 5
DNS_SOA = 6

@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class DNSANY:
    name: str
    type_: int 
    class_: int

@dataclass
class DNSHTTPS:
    name: str
    type_: int 
    class_: int

@dataclass
class DNSPTR:
    name: str
    type_: int
    class_: int
    ttl: int
    domain_name: str | bytes

@dataclass
class DNSA:
    name: str
    type_: int
    class_: int
    ttl: int
    address: str

@dataclass
class DNSAAAA:
    name: str
    type_: int
    class_: int
    ttl: int
    address: str

@dataclass
class DNSTXT:
    name: str
    type_: int
    class_: int
    ttl: int
    txt_data: list

@dataclass
class DNSCNAME:
    name: str
    type_: int
    class_: int
    ttl: int
    cname: str | bytes

@dataclass
class DNSSRV:
    name: str
    type_: int
    class_: int
    ttl: int
    priority: int
    weight: int
    port: int
    target: str

@dataclass
class DNSNSEC: # Need to work out parsing for the rr type bitmap
    name: str
    type_: int
    class_: int
    ttl: int
    next_domain_name: str | bytes
    rr_type_bitmap: bytes

@dataclass
class DNSSOA:
    name: bytes
    type_: int
    class_: int
    ttl: int
    primary_nameserver: bytes
    responsible_authority: bytes
    serial_number: int
    refresh_interval: int
    retry_interval: int
    expire_limit: int
    min_ttl: int

@dataclass
class DNSOPT:
    name: bytes | str
    type_: int
    udp_payload_size: int
    higher_bits: bytes
    edns0_version: int
    z: bytes
    options: list

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list
    answers: list
    authorities: list
    additionals: list

def process_dns_packet(packet: DNSPacket, cur_client: Client) -> None:
    """
    Function to process the data in a DNS or mDNS packet to extract
    relevant service, hostname, model, and device information.
    """
    for section in (packet.questions, packet.answers, packet.authorities, packet.additionals):
        for record in section:
            if record.name:
                decoded_name = is_utf8_decodable(record.name)
                if decoded_name:
                    cur_client.dns_names.add(decoded_name)

def decode_name(reader: BytesIO) -> bytes:
    """
    Function to perform name decoding.
    """
    parts = []
    while True:
        data = reader.read(1)
        if not data:  # If there's no more data to read, break out of the loop
            break
        length = data[0]
        if length == 0:
            break
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length: int, reader: BytesIO) -> bytes:
    """
    Function to perform DNS name decompression.
    """
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    if len(pointer_bytes) < 2:
        return None
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

def parse_header(reader: BytesIO) -> DNSHeader:
    """
    Function to parse a DNS packet header.
    """
    data = reader.read(12)
    if len(data) < 12:
        return None
    items = struct.unpack("!HHHHHH", data)

    return DNSHeader(*items)

def parse_record(reader: BytesIO, record_type: str=None) -> None | DNSPTR | DNSANY | DNSA | DNSAAAA | DNSTXT | DNSSRV | DNSNSEC | DNSOPT:
    """
    Parse DNS Record Types.
    """
    name = decode_name(reader)
    data = reader.read(4)
    if len(data) < 4:
        return None
    
    type_, class_ = struct.unpack("!HH", data)

    if type_ == DNS_ANY:
        return DNSANY(name, type_, class_)
    
    elif type_ == DNS_PTR:
        if record_type and record_type == "q":
            return DNSPTR(name, type_, class_, ttl=0, domain_name="")
        else:
            data = reader.read(4)
            if len(data) < 4:
                return DNSPTR(name, type_, class_, ttl=0, domain_name="")
            else:
                ttl = struct.unpack('!I', data)[0]
                domain_name = decode_name(reader)

            return DNSPTR(name, type_, class_, ttl, domain_name)

    elif type_ == DNS_HTTPS:
        if record_type and record_type == 'q':
            return DNSHTTPS(name, type_, class_)

    elif type_ == DNS_A:
        if record_type and record_type == 'q':
            return DNSA(name, type_, class_, 0, "")
        else:
            data = reader.read(6)
            if len(data) < 6:
                return None
            ttl, data_len = struct.unpack('!IH', data)
            if data_len == 4: # IPv4 Address (A Record)
                data = reader.read(data_len)
                address = socket.inet_ntoa(data)
                return DNSA(name, type_, class_, ttl, address)
            
    elif type_ == DNS_AAAA:
        if record_type and record_type == 'q':
            return DNSAAAA(name, type_, class_, 0, "")
        else:
            data = reader.read(6)
            if len(data) < 6:
                return None
            ttl, data_len = struct.unpack('!IH', data)
            if data_len == 16: # IPv6 Address (AAAA Record)
                data = reader.read(data_len)
                address = socket.inet_ntop(socket.AF_INET6, data)
                return DNSAAAA(name, type_, class_, ttl, address)
            
    elif type_ == DNS_CNAME:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        cname = decode_name(reader)
        return DNSCNAME(name, type_, class_, ttl, cname)
    
    elif type_ == DNS_TXT:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        txt_data_list = []  # To hold multiple strings in TXT record
        bytes_read = 0  # Counter for the number of bytes read in the TXT data
        while bytes_read < data_len:
            txt_len = int.from_bytes(reader.read(1), 'little')
            bytes_read += 1  # Update counter for TXT length byte
            if txt_len > 0:
                txt_data = reader.read(txt_len)
                bytes_read += txt_len  # Update counter for TXT data bytes
                txt_data_list.append(txt_data)
        return DNSTXT(name, type_, class_, ttl, txt_data_list)
    
    elif type_ == DNS_SRV:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        priority = weight = port = 0
        target = ""
        if data_len > 5:
            data = reader.read(6)
            priority, weight, port = struct.unpack('!HHH', data)
            data_len -= 6
            if data_len > 0:
                data = reader.read(data_len)
                target_len = data[0]
                target = data[1:1 + target_len]
        return DNSSRV(name, type_, class_, ttl, priority, weight, port, target)
    
    elif type_ == DNS_NSEC:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        # Mark the current position in the reader
        start_pos = reader.tell()
        next_domain_name = decode_name(reader)
        # Calculate the number of bytes read for the next domain name
        bytes_read_for_name = reader.tell() - start_pos
        # Calculate the remaining length for the RR type bitmaps
        rr_bitmap_len = data_len - bytes_read_for_name
        # Read the RR type bitmaps
        rr_bitmaps = reader.read(rr_bitmap_len)
        return DNSNSEC(name, type_, class_, ttl, next_domain_name, rr_bitmaps)
    
    elif type_ == DNS_SOA:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        primary_nameserver = decode_name(reader)
        responsible_authoritys_mailbox = decode_name(reader)
        data = reader.read(20)
        if len(data) < 20:
            return None
        serial_no, refresh_interval, retry_interval, expire_limit, min_ttl = struct.unpack('!IIIII', data)
        return DNSSOA(name, type_, class_, ttl, primary_nameserver, responsible_authoritys_mailbox, serial_no, \
                      refresh_interval, retry_interval, expire_limit, min_ttl)
    
    elif type_ == DNS_OPT:
        if not name:
            name = '<Root>'
        udp_payload_size = class_
        data = reader.read(6)
        if len(data) < 6:
            return None
        higher_bits, edns0_version, z, data_len = struct.unpack('!BBHH', data)
        options = []  # List to hold (code, data) tuples for each option
        # Keep track of the total bytes read for options to not exceed data_len
        bytes_read_for_options = 0
        while bytes_read_for_options < data_len:
            option_header = reader.read(4)  # Read the option code and option length
            if len(option_header) < 4:
                # End of data or malformed option, break the loop
                break
            option_code, option_len = struct.unpack('!HH', option_header)
            bytes_read_for_options += 4  # Update bytes read for option code and length
            if option_len > 0:
                # Read the option data based on the option length
                option_data = reader.read(option_len)
                bytes_read_for_options += option_len  # Update bytes read for option data
                # Append the (code, data) tuple for this option to the options list
                options.append((option_code, option_data))
            else:
                # Option with no data
                options.append((option_code, b''))

        return DNSOPT(name, type_, udp_payload_size, higher_bits, edns0_version, z, options)
    else:
        return None

def parse_dns_packet(data: bytes) -> DNSPacket:
    """
    Parse a dns packet and build a DNS dataclass stucture.
    """
    reader = BytesIO(data)
    header = parse_header(reader)

    if not header:
        return None

    # Lets use list comprehensions with a conditional clause to exclude None values
    questions = [record for record in (parse_record(reader, "q") for _ in range(header.num_questions)) if record is not None]
    answers = [record for record in (parse_record(reader) for _ in range(header.num_answers)) if record is not None]
    authorities = [record for record in (parse_record(reader) for _ in range(header.num_authorities)) if record is not None]
    additionals = [record for record in (parse_record(reader) for _ in range(header.num_additionals)) if record is not None]

    return DNSPacket(header, questions, answers, authorities, additionals)
