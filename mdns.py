#!/usr/bin/env python3

"""
Module to handle MDNS packets for ethodump-ng.
"""

from dataclasses import dataclass
from io import BytesIO
import socket
import struct
import re

from globals import clean_name, Client, ResponseObject, RedirectObject
from models import samsung_models, apple_models, hp_models, roku_models
from responses import send_response, send_spotify_response

MDNS_PTR = 12
MDNS_TXT = 16
MDNS_SRV = 33
MDNS_A = 1
MDNS_AAAA = 28
MDNS_NSEC = 47
MDNS_ANY = 255
MDNS_OPT = 41

@dataclass
class MDNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class MDNSANY:
    name: str
    type_: int 
    class_: int
    qu_bit: int

@dataclass
class MDNSPTR:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    domain_name: str

@dataclass
class MDNSA:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    address: str

@dataclass
class MDNSAAAA:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    address: str

@dataclass
class MDNSTXT:
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    txt_data: list

@dataclass
class MDNSSRV:
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
class MDNSNSEC: # Need to work out parsing for the rr type bitmap
    name: str
    type_: int
    class_: int
    qu_bit: int
    ttl: int
    next_domain_name: str
    rr_type_bitmap: bytes

@dataclass
class MDNSAuthoratativeNameservers:
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
class MDNSOPT:
    name: bytes
    type_: int
    udp_payload_size: int
    cache_flush: int
    higher_bits: bytes
    edns0_version: int
    z: bytes
    options: list

@dataclass
class MDNSPacket:
    header: MDNSHeader
    questions: list
    answers: list
    authorities: list
    additionals: list

def is_not_sha1(string: str):
    """
    Function to use a regex pattern to match a 40-character 
    hexadecimal/sha1 string. If the string is not, the
    function returns the original string; if it is, the function
    returns False
    """
    return not re.match(r'^[0-9a-fA-F]{40}$', string)

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
    elif '._tcp.local' in decoded_name:
        return decoded_name.replace('._tcp.local','')
    elif '._udp.local' in decoded_name:
        return decoded_name.replace('._udp.local','')
    return ""

def model_check(model: str) -> str:
    """
    Function to search for model identifiers in manufacture databases.
    """
    model_databases = [apple_models, hp_models, roku_models, samsung_models]

    for database in model_databases:
        result = database.get(model)
        if result:
            return result  # Return as soon as a match is found

    return None  # Return None if no match is found in any database

def parse_txt(record: MDNSTXT, cur_client: Client) -> None:
    """
    Function to parse text fields and update the Client class
    """
    device_model_tags = [b"fv", b"model", b"manufacturer", b"serialNumber", b"product"]
    connected_device_tags = [b"title", b"type", b"tech"]

    for entry in record.txt_data:
        try:
            k, v = entry.split(b'=')
        except ValueError:
            continue

        if k in connected_device_tags:
            cur_client.connections.add(v.decode('utf-8','ignore'))
        elif k in device_model_tags:
            decoded_value = v.decode('utf-8', 'ignore')
            if k == b"model" and not cur_client.model_check_complete:
                resolved_model = model_check(decoded_value.lower())
                cur_client.model_check_complete = True
                if resolved_model:
                    cur_client.oses.add('mo:' + resolved_model)
                else:
                    cur_client.oses.add('mo: ' + decoded_value)
            elif k == b"serialNumber":
                cur_client.oses.add('sn: ' + decoded_value)
            elif k == b'product':
                cur_client.oses.add('pr: ' + decoded_value)
            elif k == b'fv':
                cur_client.oses.add('fv: ' + decoded_value)
            elif k == b'manufacturer':
                cur_client.oses.add('ma: ' + decoded_value)

def process_mdns_packet(packet: MDNSPacket, cur_client: Client) -> None:
    """
    Function to process the data in a DNS or mDNS packet to extract
    relevant service, hostname, model, and device information.
    """
    service_restricted_names = ["Spotify", "google", "localhost"]
    
    def process_record(record, record_cat: str):
        """
        Function to process an mDNS record of accepted types to
        perform the task of the parent function.
        """
        hostname = None
        if record.type_ == MDNS_PTR and record_cat == 'question':
            service_name = extract_service_name(record.name)
            if service_name:
                cur_client.services.add(service_name)
                
        elif record.type_ == MDNS_PTR and record_cat == 'record':
            hostname = extract_hostname(record.domain_name)
            if hostname:
                cur_client.connections.add(hostname)
                return None
            
        # Sometimes, devices will query for a server wth an SRV record;
        # In this case, the 'name' of the record query indicates something
        # they want to connect to, not their name/hostname
        elif record.type_ == MDNS_SRV and record_cat == 'question':
            service_name = extract_service_name(record.name)
            if service_name:
                cur_client.services.add(service_name)
            return None
        
        elif record.type_ == MDNS_TXT and record_cat == 'question':
            service_name = extract_service_name(record.name)
            if service_name:
                cur_client.services.add(service_name)
            return None
        
        elif record.type_ in [MDNS_ANY, MDNS_TXT, MDNS_SRV, MDNS_A, MDNS_AAAA]:
            hostname = extract_hostname(record.name)
            if record.type_ == MDNS_SRV and record.port:
                cur_client.ports.add(record.port)
            if record.type_ == MDNS_A and not cur_client.ip_address:
                cur_client.ip_address = record.address
            if record.type_ == MDNS_AAAA and not cur_client.ipv6_address:
                cur_client.ipv6_address = record.address
            if record.type_ == MDNS_TXT:
                parse_txt(record, cur_client)
        return hostname

    hostnames = set()
    for question in packet.questions:
        hostname = process_record(question, 'question')
        if hostname and len(hostname) > 3:
            hostnames.add(hostname)
    for section in (packet.answers, packet.additionals):
        for record in section:
            hostname = process_record(record, 'record')
            if hostname and len(hostname) > 3:
                hostnames.add(hostname)

    # Cleanup and update client hostnames
    for hostname in hostnames:
        hostname_cleaned = clean_name(hostname)
        if not any(restricted_name.lower() in hostname_cleaned.lower() for restricted_name in service_restricted_names):
            sanitized_hostname = hostname_cleaned.replace('(', '').replace(')', '')
            if is_not_sha1(sanitized_hostname):
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

    if parts:
        return b".".join(parts)
    else:
        return b""

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

def parse_header(reader: BytesIO) -> MDNSHeader:
    """
    Function to parse a DNS packet header.
    """
    data = reader.read(12)
    if len(data) < 12:
        return None
    items = struct.unpack("!HHHHHH", data)

    return MDNSHeader(*items)

def parse_record(reader: BytesIO, record_type: str=None):
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

    if type_ == MDNS_ANY:
        return MDNSANY(name, type_, class_, qu_bit)
    
    elif type_ == MDNS_PTR:
        if record_type and record_type == 'question':
            return MDNSPTR(name, type_, class_, qu_bit, ttl=0, domain_name="")
        else:
            data = reader.read(4)
            if len(data) < 4:
                return MDNSPTR(name, type_, class_, qu_bit, ttl=0, domain_name="")
            else:
                ttl = struct.unpack('!I', data)[0]
                domain_name = decode_name(reader)

            return MDNSPTR(name, type_, class_, qu_bit, ttl, domain_name)
        
    elif type_ in [MDNS_A, MDNS_AAAA]:
        data = reader.read(6)
        if len(data) < 6:
            return None
        ttl, data_len = struct.unpack('!IH', data)
        if data_len == 4: # IPv4 Address (A Record)
            data = reader.read(data_len)
            address = socket.inet_ntoa(data)
            return MDNSA(name, type_, class_, qu_bit, ttl, address)
        elif data_len == 16: # IPv6 Address (AAAA Record)
            data = reader.read(data_len)
            address = socket.inet_ntop(socket.AF_INET6, data)
            return MDNSAAAA(name, type_, class_, qu_bit, ttl, address)
        else:
            return None
        
    elif type_ == MDNS_TXT:
        if record_type == 'question':
            return MDNSTXT(name, type_, class_, qu_bit, 255, [])
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
        return MDNSTXT(name, type_, class_, qu_bit, ttl, txt_data_list)
    
    elif type_ == MDNS_SRV:
        if record_type == 'question':
            return MDNSSRV(name, type_, class_, qu_bit, 0, 0, 0, 0, "")
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
        return MDNSSRV(name, type_, class_, qu_bit, ttl, priority, weight, port, target)
    
    elif type_ == MDNS_NSEC:
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
        return MDNSNSEC(name, type_, class_, qu_bit, ttl, next_domain_name, rr_bitmaps)
    
    elif type_ == MDNS_OPT:
        if not name:
            name = '<Root>'
        udp_payload_size = class_
        cache_flush = qu_bit
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

        return MDNSOPT(name, type_, udp_payload_size, cache_flush, higher_bits, edns0_version, z, options)
    else:
        return None

def parse_authority(reader: BytesIO) -> MDNSAuthoratativeNameservers:
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
    if len(data) < 20:
        return None
    serial_number, refresh_interval, retry_interval, expire_limit, min_ttl = struct.unpack("!IIIII", data)

    return MDNSAuthoratativeNameservers(name, type_, class_, ttl, data_len, primary_nameserver, \
                        responsible_authority, serial_number, refresh_interval, retry_interval, expire_limit, min_ttl)

def prepare_redirect(socket: socket.socket, ip_version: int, dst_mac, dst_ip, packet: MDNSPacket, own_iface, red_object):
    hostname = red_object.hostname
    srv_port = red_object.redirect_port
    srv_port_https = red_object.redirect_port_https
    src_mac = own_iface.mac
    src_ip = own_iface.ip
    src_ipv6 = own_iface.ipv6
    
    if packet.header.num_questions > 0 and ip_version != 6 and packet.header.flags == 0:
        actual_num_questions = len(packet.questions) 
        for i in range(min(packet.header.num_questions, actual_num_questions)):
            if packet.questions[i].type_ == MDNS_PTR and not packet.questions[i].domain_name:
                service_name = packet.questions[i].name.decode('utf-8','ignore')
                unicast = packet.questions[i].qu_bit
                resp = ResponseObject(ip_version, unicast, hostname, src_mac, src_ip, src_ipv6, dst_mac, dst_ip, service_name, srv_port, srv_port_https)
                resp_pkts = []
                # query_pkt = None
                if 'spotify' in service_name:
                    resp_pkts.append(send_spotify_response(resp))
                elif 'google' in service_name:
                    resp_pkts.append(send_response(resp, "google"))
                    resp_pkts.append(send_response(resp, "spotify"))
                elif 'airplay.' in service_name or 'hap' in service_name or 'raop' in service_name:
                    resp_pkts.append(send_response(resp,"airplay"))
                    
                    #query_pkt = send_query(resp)

                if resp_pkts:
                    for pkt in resp_pkts:
                        socket.send(pkt)
                # if query_pkt:
                #    socket.send(query_pkt)

def parse_mdns_packet(data: bytes) -> MDNSPacket:
    """
    Parse a dns packet and build a DNS dataclass stucture.
    """
    reader = BytesIO(data)
    header = parse_header(reader)

    if not header:
        return None

    # Lets use list comprehensions with a conditional clause to exclude None values
    questions = [record for record in (parse_record(reader, "question") for _ in range(header.num_questions)) if record is not None]
    answers = [record for record in (parse_record(reader) for _ in range(header.num_answers)) if record is not None]
    authorities = [record for record in (parse_record(reader) for _ in range(header.num_authorities)) if record is not None]
    additionals = [record for record in (parse_record(reader) for _ in range(header.num_additionals)) if record is not None]

    return MDNSPacket(header, questions, answers, authorities, additionals)
