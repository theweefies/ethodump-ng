#!/usr/bin/env python3

import struct
from dataclasses import dataclass
from io import BytesIO
from globals import bytes_to_mac, bytes_to_ip, bytes_to_ipv6

END_OF_OPTION_LIST = 0
NOP = 1
MAX_SEGMENT_SIZE = 2
WINDOW_SCALE = 3
SACK_PERMITTED = 4
TIMESTAMP = 8

@dataclass
class ETHHeader:
    dst_mac: str
    src_mac: str
    eth_type: bytes

@dataclass
class IPHeader:
    version: int
    header_length: int
    differentiated_service_field: int
    total_length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: bytes
    src_ip: str
    dst_ip: str
    options: bytes

@dataclass
class IPv6Header:
    verison: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ipv6: str
    dst_ipv6: str

@dataclass
class TCPHeader:
    syn_set: int
    src_port: int
    dst_port: int
    sequence_num: int
    acknowledgement_num: int
    header_length: int
    flags: int
    window_size: int
    checksum: bytes
    urgent_pointer: int
    payload_length: int
    options:bytes

@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: bytes
    payload_length: int

def tcp_ip_fingerprint(ip_header: IPHeader, tcp_header: TCPHeader) -> None:
    """
    Function to prepare tcp/ip fingerprint from SYN frame
    """
    ttl = ip_header.ttl
    frame_size = ip_header.total_length
    ip_flags = ip_header.flags
    win_size = tcp_header.window_size
    
    mss = None
    window_scale = None
    sack_permitted = False
    timestamp_val = timestamp_reply = None
    nops = 0

    if tcp_header.options:
        i = 0
        while i < len(tcp_header.options):
            kind = tcp_header.options[i]
            if kind == END_OF_OPTION_LIST:
                break
            elif kind == NOP:
                nops += 1
                i += 1
                continue
            else:
                length = tcp_header.options[i+1]
                if kind == MAX_SEGMENT_SIZE:
                    mss = struct.unpack('!H', tcp_header.options[i+2:i+length])[0]
                elif kind == WINDOW_SCALE:
                    window_scale = tcp_header.options[i+2]
                elif kind == SACK_PERMITTED:
                    sack_permitted = True
                elif kind == TIMESTAMP:
                    timestamp_val, timestamp_reply = struct.unpack('!II', tcp_header.options[i+2:i+length])
            i += length
    
    flags = tcp_header.flags
    # IP Header flag parsing
    dnf = (ip_flags & 0x02) >> 1
    mfs = ip_flags & 0x01
    # TCP Header flag parsing
    res = (flags & 0x0e00) >> 9
    nonce = (flags & 0x0100) >> 8
    cwr = (flags & 0x0080) >> 7
    ecn = (flags & 0x0040) >> 6
    urg = (flags & 0x0020) >> 5
    ack = (flags & 0x0010) >> 4
    psh = (flags & 0x0008) >> 3
    rst = (flags & 0x0004) >> 2
    syn = (flags & 0x0002) >> 1
    fin = flags & 0x0001

def parse_eth_header(reader: BytesIO) -> ETHHeader | None:
    """
    Ethernet Header Parsing Function
    """
    data = reader.read(14)
    if len(data) < 14:
        return None
    dst_mac_bytes, src_mac_bytes, eth_type = struct.unpack('!6s6s2s', data)
    dst_mac = bytes_to_mac(dst_mac_bytes)
    src_mac = bytes_to_mac(src_mac_bytes)

    return ETHHeader(dst_mac, src_mac, eth_type)

def parse_ip_header(reader: BytesIO) -> IPHeader | None:
    """
    IPv4 Header Parsing Function
    """
    data = reader.read(20)
    if len(data) < 20:
        return None
    ver_len = data[0]
    version = (ver_len & 0xF0) >> 4
    header_length = (ver_len & 0x0F) * 4 # to resolve to the actual number of bytes
    dsf = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = struct.unpack('!H',data[4:6])[0]
    flags = data[6] >> 5 # stores the 3x MSBs
    frag_offset = struct.unpack('!H', data[6:8])[0] & 0x1FFF
    ttl = data[8]
    proto = data[9]
    checksum = data[10:12]
    src_ip = bytes_to_ip(data[12:16])
    dst_ip = bytes_to_ip(data[16:20])
    options = b''
    if header_length > 20:
        options = reader.read(header_length - 20)

    return IPHeader(version, header_length, dsf, total_length, identification, \
                    flags, frag_offset, ttl, proto, checksum, src_ip, dst_ip, options)

def parse_ipv6_header(reader: BytesIO) -> IPv6Header | None:
    """
    IPv6 Header Parsing Function
    """
    data = reader.read(40)
    if len(data) < 40:
        return None
    version = (data[0] & 0xF0) >> 4
    payload_length, next_header, hop_limit = struct.unpack('!HBB', data[4:8])
    src_ipv6 = bytes_to_ipv6(data[8:24])
    dst_ipv6 = bytes_to_ipv6(data[24:40])
    if next_header == 0: # icmpv6
        data = reader.read(8)
        
    return IPv6Header(version, payload_length, next_header,\
                      hop_limit, src_ipv6, dst_ipv6)

def parse_udp_header(reader: BytesIO) -> UDPHeader | None:
    """
    UDP Header Parsing Function
    """
    data = reader.read(8)
    if len(data) < 8:
        return None
    src_port, dst_port, udp_total_len = struct.unpack('!HHH', data[:6])
    checksum = data[6:8]
    udp_payload_len = udp_total_len - 8

    return UDPHeader(src_port, dst_port, udp_total_len, checksum, udp_payload_len)

def parse_tcp_header(reader: BytesIO) -> TCPHeader | None:
    """
    TCP Header Parsing Function
    """
    data = reader.read(20)
    if len(data) < 20:
        return None
    src_port, dst_port, seq_num, ack_num = struct.unpack('!HHII', data[:12])
    header_length = ((data[12] & 0xF0) >> 4) * 4 # to resolve to bytes
    flags = struct.unpack('!H', data[12:14])[0] & 0x0FFF
    syn = (flags & 0x0002) >> 1
    window_size = struct.unpack('!H', data[14:16])[0]
    checksum = data[16:18]
    urgent_pointer = struct.unpack('!H', data[18:20])[0]
    if header_length > 20:
        data = reader.read(header_length - 20)
        options = data
    else:
        options = b''

    # we set the payload length to 0 because this will be set later -> math ->
    return TCPHeader(syn, src_port, dst_port, seq_num, ack_num, header_length, \
                    flags, window_size, checksum, urgent_pointer, 0, options)