#!/usr/bin/env python3

"""
Module to handle MDNS packets for ethodump-ng.
"""

from dataclasses import dataclass
from io import BytesIO
import socket
import struct
import re
import random
import hashlib
import time
import uuid

from globals import clean_name, Client, mdns_queue, mac_address_to_bytes, ETH_P
from models import samsung_models, apple_models, hp_models, roku_models

MDNS_PTR = 12
MDNS_TXT = 16
MDNS_SRV = 33
MDNS_A = 1
MDNS_AAAA = 28
MDNS_NSEC = 47
MDNS_ANY = 255
MDNS_OPT = 41

MULTICAST_IP = '224.0.0.251'
MULTICAST_MAC = '01:00:5e:00:00:fb'
UDP_HEADER_LEN = 8
IP_HEADER_LEN = 20

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
    domain_name: str | bytes

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
    next_domain_name: str | bytes
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
    name: bytes | str
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

def is_not_sha1(string: str) -> bool | str:
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
    return ""

def model_check(model: str) -> None | str:
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
                    cur_client.oses.add(resolved_model)
                else:
                    cur_client.oses.add(decoded_value)
            elif k != b"model":
                cur_client.oses.add(decoded_value)
        # print('Key: ', k.decode('utf-8','ignore'))
        # print('Value: ', v.decode('utf-8','ignore'))

def process_mdns_packet(packet: MDNSPacket, cur_client: Client) -> None:
    """
    Function to process the data in a DNS or mDNS packet to extract
    relevant service, hostname, model, and device information.
    """
    service_restricted_names = ["Spotify", "google", "localhost"]
    
    def process_record(record: MDNSA | MDNSAAAA | MDNSANY | MDNSPTR | MDNSNSEC | MDNSSRV | MDNSTXT, record_cat: str) -> None | str | bytes:
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
            
        # Sometimes, devices will query for a SeRVer wth an SRV record;
        # In this case, the 'name' of the record query indicates something
        # they want to connect to, not their name/hostname
        elif record.type_ == MDNS_SRV and record_cat == 'question':
            hostname = extract_hostname(record.name)
            cur_client.connections.add(hostname)
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

def parse_header(reader: BytesIO) -> MDNSHeader:
    """
    Function to parse a DNS packet header.
    """
    data = reader.read(12)
    if len(data) < 12:
        return None
    items = struct.unpack("!HHHHHH", data)

    return MDNSHeader(*items)

def parse_record(reader: BytesIO, record_type: str=None) -> None | MDNSPTR | MDNSANY | MDNSA | MDNSAAAA | MDNSTXT | MDNSSRV | MDNSNSEC | MDNSOPT:
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

def parse_authority(reader: BytesIO) -> MDNSAuthoratativeNameservers | None:
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

def ip_checksum(ip_header):
    assert len(ip_header) % 2 == 0, "Header length must be even."

    checksum = 0
    for i in range(0, len(ip_header), 2):
        word = (ip_header[i] << 8) + ip_header[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff

def udp_checksum(src_addr, dest_addr, udp_length, udp_header, udp_data):
    """
    Calculate the UDP checksum including the pseudo-header.
    """
    # Pseudo-header fields
    protocol = 17  # UDP protocol number
    pseudo_header = struct.pack('!4s4sBBH', 
                                socket.inet_aton(src_addr), 
                                socket.inet_aton(dest_addr), 
                                0, 
                                protocol, 
                                udp_length)

    # Calculate the checksum including pseudo-header
    checksum = 0
    # Process the pseudo-header
    for i in range(0, len(pseudo_header), 2):
        word = (pseudo_header[i] << 8) + pseudo_header[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # Process the UDP header
    for i in range(0, len(udp_header), 2):
        word = (udp_header[i] << 8) + udp_header[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # Process the data
    if len(udp_data) % 2:  # if odd length, pad with a zero byte
        udp_data += b'\x00'
    for i in range(0, len(udp_data), 2):
        word = (udp_data[i] << 8) + udp_data[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff

def create_udp_header(src_port, dst_port, length, checksum):
    
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)

def encode_mdns_name(name):
    """Encode a domain name according to mDNS requirements."""
    parts = name.split('.')
    encoded_parts = [len(part).to_bytes(1, 'big') + part.encode() for part in parts]
    return b''.join(encoded_parts) + b'\x00'

def generate_hex_string(length):
    hex_digits = "0123456789abcdef"
    random.seed(time.time())
    
    hex_string = ''.join(random.choice(hex_digits) for _ in range(length))
    
    return hex_string


def send_spotify_response(service_name, src_mac, src_ip, hostname, skt: socket.socket):
    
    # mdns payload
    transaction_id = b'\x00\x00'
    flags = b'\x84\x00'
    questions = b'\x00\x00'
    answer_rrs = b'\x00\x02'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x08'

    airplay_target = "_airplay._tcp.local"
    full_airplay_name_field = encode_mdns_name(hostname + '.' + airplay_target)
    full_spotify_name_field = encode_mdns_name(hostname + '.' + service_name)

    ################ SPOTIFY PTR RECORD ##################
    name_field = encode_mdns_name(service_name)

    type_ = struct.pack('!H', MDNS_PTR)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)
    
    #sha1_hash = hashlib.sha1(src_mac.encode())
    #sha1_hex = sha1_hash.hexdigest()
    domain_name_text = hostname + '.' + service_name
    encoded_domain_name = encode_mdns_name(domain_name_text)
    data_len = len(encoded_domain_name) + 2
    domain_name = encoded_domain_name + b'\xc0\x0c'

    spotify_ptr_record = name_field + type_ + class_ + time_to_live + int(data_len).to_bytes(2, 'big') + domain_name

    ################ AIRPLAY PTR RECORD ##################
    name_field = encode_mdns_name(airplay_target)
    
    domain_name_text = hostname + '.' + airplay_target
    encoded_domain_name = encode_mdns_name(domain_name_text)
    data_len = len(encoded_domain_name) + 2
    domain_name = encoded_domain_name + b'\xc0\x0c'

    airplay_ptr_record = name_field + type_ + class_ + time_to_live + int(data_len).to_bytes(2, 'big') + domain_name

    ################## MDNS TXT RECORD ###################
    type_ = struct.pack('!H', MDNS_TXT)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    device_id = src_mac.upper()
    psi_mac = src_mac.replace(':','').upper()
    txt_acl = "acl=0".encode()
    txt_acl_len = struct.pack('!B',len(txt_acl))
    txt_deviceid = f"deviceid={device_id}".encode()
    txt_deviceid_len = struct.pack('!B',len(txt_deviceid))
    txt_features = "features=0x7F8AD0,0x38BCF46".encode()
    txt_features_len = struct.pack('!B',len(txt_features))
    txt_fex = "fex=0Ip/AEbPiwNACA".encode()
    txt_fex_len = struct.pack('!B',len(txt_fex))
    txt_rsf = "rsf=0x3".encode()
    txt_rsf_len = struct.pack('!B',len(txt_rsf))
    txt_fv = "fv=p20.10.00.4102".encode()
    txt_fv_len = struct.pack('!B',len(txt_fv))
    txt_at = "at=0x1".encode()
    txt_at_len = struct.pack('!B',len(txt_at))
    txt_flags = "flags=0x244".encode()
    txt_flags_len = struct.pack('!B',len(txt_flags))
    txt_model = "model=appletv6,2".encode()
    txt_model_len = struct.pack('!B',len(txt_model))
    txt_integrator = "integrator=sony_tv".encode()
    txt_integrator_len = struct.pack('!B',len(txt_integrator))
    txt_manufacturer = "manufacturer=Sony".encode()
    txt_manufacturer_len = struct.pack('!B',len(txt_manufacturer))
    txt_serial_number = f"serialNumber={str(uuid.uuid4())}".encode()
    txt_serial_number_len = struct.pack('!B',len(txt_serial_number))
    txt_protovers = "protovers=1.1".encode()
    txt_protovers_len = struct.pack('!B',len(txt_protovers))
    txt_srcvers = "srcvers=377.40.00".encode()
    txt_srcvers_len = struct.pack('!B',len(txt_srcvers))
    txt_pi = f"pi={device_id}".encode()
    txt_pi_len = struct.pack('!B',len(txt_pi))
    txt_psi = f"psi=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_psi_len = struct.pack('!B',len(txt_psi))
    txt_gid = f"gid=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_gid_len = struct.pack('!B',len(txt_gid))
    txt_gcgl = "gcgl=0".encode()
    txt_gcgl_len = struct.pack('!B',len(txt_gcgl))
    txt_pk = f"pk={generate_hex_string(64)}".encode()
    print(txt_pk)
    txt_pk_len = struct.pack('!B',len(txt_pk))

    txt_payload = txt_acl_len + txt_acl + txt_deviceid_len + txt_deviceid + txt_features_len + txt_features + txt_fex_len + txt_fex +\
        txt_rsf_len + txt_rsf + txt_fv_len + txt_fv + txt_at_len + txt_at + txt_flags_len + txt_flags + txt_model_len + txt_model +\
        txt_integrator_len + txt_integrator + txt_manufacturer_len + txt_manufacturer + txt_serial_number_len + txt_serial_number +\
        txt_protovers_len + txt_protovers + txt_srcvers_len + txt_srcvers + txt_pi_len + txt_pi + txt_psi_len + txt_psi + txt_gid_len +\
        txt_gid + txt_gcgl_len + txt_gcgl + txt_pk_len + txt_pk

    txt_payload_len = struct.pack('!H', len(txt_payload))
    txt_record = full_airplay_name_field + type_ + class_ + time_to_live + txt_payload_len + txt_payload

    ################## MDNS SRV RECORD ###################
    type_ = struct.pack('!H', MDNS_SRV)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    priority = struct.pack('!H', 0)
    weight = struct.pack('!H', 0)
    port = struct.pack('!H', 7000)
    target = encode_mdns_name(hostname + '.' + 'local')
    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))

    srv_record = full_airplay_name_field + type_ + class_ + time_to_live + srv_data_len + srv_data

    ################## MDNS TXT RECORD ###################
    type_ = struct.pack('!H', MDNS_TXT)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    txt_cpath = "CPath=/zc".encode()
    txt_cpath_len = struct.pack('!B',len(txt_cpath))

    txt_payload = txt_cpath_len + txt_cpath
    txt_payload_len = struct.pack('!H', len(txt_payload))
    txt_record_spotify = full_spotify_name_field + type_ + class_ + time_to_live + txt_payload_len + txt_payload

    ################## MDNS SRV RECORD ###################
    type_ = struct.pack('!H', MDNS_SRV)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    priority = struct.pack('!H', 0)
    weight = struct.pack('!H', 0)
    port = struct.pack('!H', 7000)
    target = encode_mdns_name(hostname + '.' + 'local')
    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))

    srv_record_spotify = full_spotify_name_field + type_ + class_ + time_to_live + srv_data_len + srv_data

    #################### MDNS A RECORD ####################
    domain_name = encode_mdns_name(hostname + '.' + 'local')
    type_ = struct.pack('!H', MDNS_A)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    ip_bytes = socket.inet_aton(src_ip)
    a_data_len = struct.pack('!H', len(ip_bytes))

    a_record = domain_name + type_ + class_ + time_to_live + a_data_len + ip_bytes

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
    nsec_data_len = struct.pack('!H',len(full_airplay_name_field) + len(nsec_bitmap))

    nsec_srv_txt_airplay_record = full_airplay_name_field + type_ + class_ + time_to_live + nsec_data_len + full_airplay_name_field + nsec_bitmap

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
    nsec_data_len = struct.pack('!H',len(full_spotify_name_field) + len(nsec_bitmap))

    nsec_srv_txt_spotify_record = full_spotify_name_field + type_ + class_ + time_to_live + nsec_data_len + full_spotify_name_field + nsec_bitmap

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    nsec_bitmap = b'\x00\x04\x40\x00\x00\x00'
    nsec_data_len = struct.pack('!H',len(domain_name) + len(nsec_bitmap))

    nsec_a_record = domain_name + type_ + class_ + time_to_live + nsec_data_len + domain_name + nsec_bitmap

    ################ BUILD MDNS PAYLOAD ##################
    mdns_payload = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + spotify_ptr_record + airplay_ptr_record +\
        txt_record + srv_record + txt_record_spotify + srv_record_spotify + a_record + nsec_srv_txt_airplay_record + nsec_srv_txt_spotify_record + nsec_a_record
    mdns_len = len(mdns_payload)

    # ethernet header
    multicast_mac = mac_address_to_bytes(MULTICAST_MAC)
    src_mac = mac_address_to_bytes(src_mac)
    eth_header = struct.pack("!6s6sH", multicast_mac, src_mac, 0x0800)

    # ip header
    multicast_ip = MULTICAST_IP
    ver_header_len = 69 # version 4 + header length 20 (5)
    dsf = 0 # DSF
    identification = random.randint(0, 0xFFFF)
    ip_header_len = IP_HEADER_LEN
    udp_header_len = UDP_HEADER_LEN
    ttl = 255
    ip_proto_udp = 17
    flags_fragment_offset = 0
    checksum = 0

    # udp header
    header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

    calculated_checksum = ip_checksum(header_without_checksum)

    ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, calculated_checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

    udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
    checksum = udp_checksum(src_ip, multicast_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
    udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

    pkt = eth_header + ip_header + udp_header_with_checksum + mdns_payload

    skt.send(pkt)
    return

def send_airplay_response(src_mac, src_ip, hostname, socket):
    pass

def prepare_redirect(target_ip, src_mac, src_ip, socket, packet: MDNSPacket, hostname: str):
    if packet.header.num_questions > 0:
        service_name_list = []
        for i in range(0,packet.header.num_questions):
            service_name_list.append(packet.questions[i].name.decode('utf-8','ignore'))
        for service_name in service_name_list:
            if 'spotify' in service_name:
                send_spotify_response(service_name, src_mac, src_ip, hostname, socket)
            if 'airplay' in service_name:
                send_airplay_response(src_mac, src_ip, hostname, socket)

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
