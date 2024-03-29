#!/usr/bin/env python3

import struct
import socket
from typing import List
from dataclasses import dataclass, field

@dataclass
class ARP:
    hardware_type: int
    protocol: bytes
    hardware_size: int
    protocol_size: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

@dataclass
class ETHHeader:
    dst_mac: str
    src_mac: str
    eth_type: bytes

@dataclass
class IPHeader:
    version: int
    header_length: int
    differentiated_service_field: bytes
    total_length: int
    identification: bytes
    flags: bytes
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
    src_port: int
    dst_port: int
    sequence_num: int
    acknowledgement_num: int
    header_length: int
    flags: bytes
    windows_size: int
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

def bytes_to_mac(bytes):
    """
    Converts a bytes MAC to a colon delimited string.
    """
    return ':'.join('{:02x}'.format(b) for b in bytes)

def bytes_to_ip(bytes):

    return socket.inet_ntoa(bytes)

def bytes_to_ipv6(bytes):

    return socket.inet_ntop(socket.AF_INET6, bytes)

def parse_arp(reader):
    data = reader.read(28)
    hardware_type = struct.unpack('!H', data[:2])[0]
    protocol = data[2:4]
    hardware_size = data[4]
    protocol_size = data[5]
    opcode = struct.unpack('!H', data[6:8])[0]
    sender_mac = bytes_to_mac(data[8:14])
    sender_ip = bytes_to_ip(data[14:18])
    target_mac = bytes_to_mac(data[18:24])
    target_ip = bytes_to_ip(data[24:28])

    return ARP(hardware_type, protocol, hardware_size, protocol_size, \
               opcode, sender_mac, sender_ip, target_mac, target_ip)

def parse_eth_header(reader):
    data = reader.read(14)
    dst_mac_bytes, src_mac_bytes, eth_type = struct.unpack('!6s6s2s', data)
    dst_mac = bytes_to_mac(dst_mac_bytes)
    src_mac = bytes_to_mac(src_mac_bytes)

    return ETHHeader(dst_mac, src_mac, eth_type)

def parse_ip_header(reader):
    data = reader.read(20)
    ver_len = data[0]
    version = (ver_len & 0xF0) >> 4
    header_length = (ver_len & 0x0F) * 4 # to resolve to bytes
    dsf = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = data[4:6]
    flags = data[6:8]
    ttl = data[8]
    proto = data[9]
    checksum = data[10:12]
    src_ip = bytes_to_ip(data[12:16])
    dst_ip = bytes_to_ip(data[16:20])
    options = b''
    if header_length > 20:
        options = reader.read(header_length - 20)

    return IPHeader(version, header_length, dsf, total_length, identification, \
                    flags, ttl, proto, checksum, src_ip, dst_ip, options)

def parse_ipv6_header(reader):
    data = reader.read(40)
    version = (data[0] & 0xF0) >> 4
    payload_length, next_header, hop_limit = struct.unpack('!HBB', data[4:8])
    src_ipv6 = bytes_to_ipv6(data[8:24])
    dst_ipv6 = bytes_to_ipv6(data[24:40])
    if next_header == 0: # icmpv6
        data = reader.read(8)
        
    return IPv6Header(version, payload_length, next_header,\
                      hop_limit, src_ipv6, dst_ipv6)

def parse_udp_header(reader):
    data = reader.read(8)
    src_port = struct.unpack('!H', data[:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    udp_total_len = struct.unpack('!H', data[4:6])[0]
    checksum = data[6:8]
    udp_payload_len = udp_total_len - 8

    return UDPHeader(src_port, dst_port, udp_total_len, checksum, udp_payload_len)

def parse_tcp_header(reader):
    data = reader.read(20)
    src_port = struct.unpack('!H', data[:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    seq_num = struct.unpack('!I', data[4:8])[0]
    ack_num = struct.unpack('!I', data[8:12])[0]
    header_length = ((data[12] & 0xF0) >> 4) * 4 # to resolve to bytes
    flags = struct.unpack('!H', data[12:14])[0] & 0x0FFF
    window_size = struct.unpack('!H', data[14:16])[0]
    checksum = data[16:18]
    urgent_pointer = data[18:20]
    if header_length > 20:
        data = reader.read(header_length - 20)
        options = data
    else:
        options = b''

    return TCPHeader(src_port, dst_port, seq_num, ack_num, header_length, \
                    flags, window_size, checksum, urgent_pointer, 0, options)