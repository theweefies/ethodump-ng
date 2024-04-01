#!/usr/bin/env python3

"""
Module to handle DNS and MDNS packets for ethodump-ng.
"""

from dataclasses import dataclass
from io import BytesIO
import socket
import struct
import re

from globals import clean_name, Client

DNS_PTR = 12
DNS_TXT = 16
DNS_SRV = 33
DNS_A = 1
DNS_AAAA = 28
DNS_NSEC = 47
DNS_ANY = 255
DNS_OPT = 41

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
    qu_bit: int

@dataclass
class DNSPTR:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    domain_name: str | bytes

@dataclass
class DNSA:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    address: str

@dataclass
class DNSAAAA:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    address: str

@dataclass
class DNSTXT:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    txt_data: list

@dataclass
class DNSSRV:
    name: str
    type_: int
    class_: int
    qu_bit: int
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
    qu_bit: int
    ttl: int
    next_domain_name: str | bytes
    rr_type_bitmap: bytes

@dataclass
class DNSAuthoratativeNameservers:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data_len: int
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
    cache_flush: int
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

def extract_hostname(data: bytes) -> str:
    """
    Extract hostname from the PTR record in an answer.
    """
    if not data:
        return ""
    try:
        decoded_data = data.decode('utf-8', 'ignore')
        hostname = decoded_data.split('.', 1)[0]
    except UnicodeDecodeError:
        hostname = str(data.split(b'.', 1)[0])
        pass
    
    return hostname

def extract_service_name(name: bytes) -> str:
    """
    Extract service name from any name field starting with '_'.
    """
    try:
        decoded_name = name.decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        decoded_name = str(name)
        pass
    service_match = re.match(r'_([^._]+)', decoded_name)
    if service_match:
        return service_match.group(1)  # Service name without the leading '_'
    return ""

def parse_txt(record: DNSTXT, cur_client: Client) -> None:
    """
    Function to parse text fields and update the Client class
    """
    device_model_tags = [b"fv", b"model", b"manufacturer", b"serialNumber"]
    connected_device_tags = [b"title", b"type", b"tech"]

    for entry in record.txt_data:
        k, v = entry.split(b'=')
        if k in connected_device_tags:
            cur_client.connections.add(v.decode('utf-8','ignore'))
        elif k in device_model_tags:
            cur_client.oses.add(v.decode('utf-8', 'ignore'))
        # print('Key: ', k.decode('utf-8','ignore'))
        # print('Value: ', v.decode('utf-8','ignore'))

def process_dns_packet(packet: DNSPacket, cur_client: Client) -> None:
    """
    Function to process the data in a DNS or mDNS packet to extract
    relevant service, hostname, model, and device information.
    """
    service_restricted_names = ["Spotify", "google", "localhost"]
    
    def process_record(record: DNSA | DNSAAAA | DNSANY | DNSPTR | DNSNSEC | DNSSRV | DNSTXT, record_type: str) -> None | str | bytes:
        """
        Function to process an mDNS record of accepted types to
        perform the task of the parent function.
        """
        hostname = None
        if record.type_ == DNS_PTR and record_type == 'question':
            service_name = extract_service_name(record.name)
            if service_name:
                cur_client.services.add(service_name)
        elif record.type_ in [DNS_ANY, DNS_TXT, DNS_SRV, DNS_A, DNS_AAAA]:
            hostname = extract_hostname(record.name)
            if record.type_ == DNS_SRV and record.port:
                cur_client.ports.add(record.port)
            if record.type_ == DNS_A and not cur_client.ip_address:
                cur_client.ip_address = record.address
            if record.type_ == DNS_AAAA and not cur_client.ipv6_address:
                cur_client.ipv6_address = record.address
            if record.type_ == DNS_TXT:
                parse_txt(record, cur_client)
        return hostname

    hostnames = set()
    for question in packet.questions:
        hostname = process_record(question, 'question')
        if hostname:
            hostnames.add(hostname)
    for section in (packet.answers, packet.additionals):
        for record in section:
            hostname = process_record(record, 'record')
            if hostname:
                hostnames.add(hostname)

    # Cleanup and update client hostnames
    for hostname in hostnames:
        if len(hostname) > 3:
            hostname_cleaned = clean_name(hostname)
            lowercase_hostname = hostname_cleaned.lower()
            if not any(restricted_name.lower() in lowercase_hostname for restricted_name in service_restricted_names):
                sanitized_hostname = hostname_cleaned.replace('(', '').replace(')', '')
                cur_client.hostnames.add(sanitized_hostname)

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
    items = struct.unpack("!HHHHHH", reader.read(12))
    # see "a note on BytesIO" for an explanation of `reader` here
    return DNSHeader(*items)

def parse_record(reader: BytesIO, record_type: str=None) -> None | DNSPTR | DNSANY | DNSA | DNSAAAA | DNSTXT | DNSSRV | DNSNSEC | DNSOPT:
    """
    Parse M/DNS Record Types.
    """
    name = decode_name(reader)
    data = reader.read(4)
    if len(data) < 4:
        return None
    
    type_, class_with_qu_bit = struct.unpack("!HH", data)

    # Extract the QU bit (the most significant bit of the class field)
    qu_bit = class_with_qu_bit >> 15  # Shift right by 15 bits to get the MSB
    # Mask out the QU bit to get the actual class value
    class_ = class_with_qu_bit & 0x7FFF  # 0x7FFF (binary 0111 1111 1111 1111) masks out the MSB

    if type_ == DNS_ANY:
        return DNSANY(name, type_, class_, qu_bit)
    
    elif type_ == DNS_PTR:
        if record_type and record_type == "q":
            return DNSPTR(name, type_, class_, qu_bit, ttl=0, domain_name="")
        else:
            data = reader.read(4)
            if len(data) < 4:
                return DNSPTR(name, type_, class_, qu_bit, ttl=0, domain_name="")
            else:
                ttl = struct.unpack('!I', data)[0]
                domain_name = decode_name(reader)

            return DNSPTR(name, type_, class_, qu_bit, ttl, domain_name)
        
    elif type_ in [DNS_A, DNS_AAAA]:
        data = reader.read(4)
        if len(data) < 4:
            return None
        ttl = struct.unpack('!I', data)[0]
        data = reader.read(2)
        if len(data) < 2:
            return None
        data_len = struct.unpack('!H', data)[0]
        if data_len == 4: # IPv4 Address (A Record)
            data = reader.read(data_len)
            address = socket.inet_ntoa(data)
            return DNSA(name, type_, class_, qu_bit, ttl, address)
        elif data_len == 16: # IPv6 Address (AAAA Record)
            data = reader.read(data_len)
            address = socket.inet_ntop(socket.AF_INET6, data)
            return DNSAAAA(name, type_, class_, qu_bit, ttl, address)
        else:
            return None
        
    elif type_ == DNS_TXT:
        data = reader.read(4)
        ttl = struct.unpack('!I', data)[0]
        data = reader.read(2)
        data_len = struct.unpack('!H', data)[0]
        txt_data_list = []  # To hold multiple strings in TXT record
        bytes_read = 0  # Counter for the number of bytes read in the TXT data
        while bytes_read < data_len:
            txt_len = int.from_bytes(reader.read(1), 'little')
            bytes_read += 1  # Update counter for TXT length byte
            if txt_len > 0:
                txt_data = reader.read(txt_len)
                bytes_read += txt_len  # Update counter for TXT data bytes
                txt_data_list.append(txt_data)
        return DNSTXT(name, type_, class_, qu_bit, ttl, txt_data_list)
    
    elif type_ == DNS_SRV:
        data = reader.read(4)
        ttl = struct.unpack('!I', data)[0]
        data = reader.read(2)
        data_len = struct.unpack('!H', data)[0]
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
        return DNSSRV(name, type_, class_, qu_bit, ttl, priority, weight, port, target)
    
    elif type_ == DNS_NSEC:
        data = reader.read(4)
        ttl = struct.unpack('!I', data)[0]
        data = reader.read(2)
        data_len = struct.unpack('!H', data)[0]
        # Mark the current position in the reader
        start_pos = reader.tell()
        next_domain_name = decode_name(reader)
        # Calculate the number of bytes read for the next domain name
        bytes_read_for_name = reader.tell() - start_pos
        # Calculate the remaining length for the RR type bitmaps
        rr_bitmap_len = data_len - bytes_read_for_name
        # Read the RR type bitmaps
        rr_bitmaps = reader.read(rr_bitmap_len)
        return DNSNSEC(name, type_, class_, qu_bit, ttl, next_domain_name, rr_bitmaps)
    
    elif type_ == DNS_OPT:
        if not name:
            name = '<Root>'
        udp_payload_size = class_
        cache_flush = qu_bit
        higher_bits, edns0_version, z = struct.unpack('!BBH', reader.read(4))
        data_len = struct.unpack('!H', reader.read(2))[0]
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

        return DNSOPT(name, type_, udp_payload_size, cache_flush, higher_bits, edns0_version, z, options)
    else:
        return None

def parse_authority(reader: BytesIO) -> DNSAuthoratativeNameservers | None:
    """
    Parses a dns authoratative nameserver record.
    """
    name = decode_name(reader)
    if not name:
        name = b'<Root>'
    data = reader.read(10)
    if len(data) < 10:
        return None
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    primary_nameserver = decode_name(reader)
    if not primary_nameserver:
        primary_nameserver = b'<Root>'
    responsible_authority = decode_name(reader)
    data = reader.read(20)
    serial_number, refresh_interval, retry_interval, expire_limit, min_ttl = struct.unpack("!IIIII", data)

    return DNSAuthoratativeNameservers(name, type_, class_, ttl, data_len, primary_nameserver, \
                        responsible_authority, serial_number, refresh_interval, retry_interval, expire_limit, min_ttl)

def parse_dns_packet(data: bytes) -> DNSPacket:
    """
    Parse a dns packet and build a DNS dataclass stucture.
    """
    reader = BytesIO(data)
    header = parse_header(reader)

    # Lets use list comprehensions with a conditional clause to exclude None values
    questions = [record for record in (parse_record(reader, "q") for _ in range(header.num_questions)) if record is not None]
    answers = [record for record in (parse_record(reader) for _ in range(header.num_answers)) if record is not None]
    authorities = [record for record in (parse_record(reader) for _ in range(header.num_authorities)) if record is not None]
    additionals = [record for record in (parse_record(reader) for _ in range(header.num_additionals)) if record is not None]

    return DNSPacket(header, questions, answers, authorities, additionals)
