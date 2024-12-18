#!/usr/bin/env python3
"""
TLS Module for ethodump-ng
"""
from io import BytesIO
import struct
import hashlib
from typing import Union, List
from dataclasses import dataclass

from models import ja3_tls_vals
from globals import Client

TLS_V1_0 = b'\x03\x01'
TLS_V1_2 = b'\x03\x03'

TLS_CLIENT_HELLO = 1

GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}

@dataclass
class TLSExtension:
    type_: int
    data: Union[bytes, List[int]]

@dataclass
class TLSClientHello:
    type_: int
    tls_version: bytes
    chello_version: bytes
    random: bytes
    session_id: int
    cipher_suites: list
    compression_methods: list
    extensions: list

def three_bytes_to_int(byte_sequence: bytes) -> int:
    """
    Function to unpack a three byte sequence into an integer.
    """
    # Ensure the byte sequence is exactly 3 bytes
    if len(byte_sequence) != 3:
        return -1
    
    # Pad the byte sequence to 4 bytes (since integers are 4 bytes)
    padded_sequence = b'\x00' + byte_sequence

    # Unpack as a 4-byte integer (big-endian) and return
    return struct.unpack('!I', padded_sequence)[0]        

def parse_sni_extension(extension_data: bytes) -> List[str]:
    """
    Parse the Server Name Indication extension to extract server names.

    :param extension_data: The raw bytes of the SNI extension data.
    :return: A list of server names (hostnames) in plaintext.
    """
    sni_list = []
    stream = BytesIO(extension_data)

    # The first two bytes represent the length of the server name list
    server_name_list_length = struct.unpack("!H", stream.read(2))[0]
    list_end = stream.tell() + server_name_list_length

    while stream.tell() < list_end:
        # The first byte is the server name type
        name_type = struct.unpack("!B", stream.read(1))[0]

        # The next two bytes represent the server name length
        name_length = struct.unpack("!H", stream.read(2))[0]

        # The next 'name_length' bytes represent the server name
        if name_type == 0:  # Type 0 is for hostnames
            server_name = stream.read(name_length).decode('utf-8')
            sni_list.append(server_name)
        else:
            # Skip this server name if it's not a hostname
            stream.read(name_length)

    return sni_list

def find_ja3_classification(tls: TLSClientHello, cur_client: Client) -> None:
    """
    Function to create the ja3 string, digest, and look up ja3 classification
    """
    sni_list = []
    # SSL Version
    ssl_version = int.from_bytes(tls.chello_version, "big")

    # Cipher Suites
    cipher_suites = "-".join(str(cs) for cs in tls.cipher_suites if cs not in GREASE_TABLE)

    # Extensions
    extensions = ""
    elliptic_curve = ""
    elliptic_curve_point_format = ""

    for ext in tls.extensions:
        ext_type = ext.type_
        ext_data = ext.data

        # Checking for GREASE values (https://tools.ietf.org/html/draft-ietf-tls-grease-01)
        if ext_type in GREASE_TABLE:
            continue

        if ext_type == 0:
            sni_list = parse_sni_extension(ext_data)

        extensions += str(ext_type) + "-"

        # Supported Groups (Elliptic Curves)
        if ext_type == 0x0a:  # 0x0a is the type for Supported Groups
            # Assuming ext_data is the list of supported groups
            elliptic_curve = "-".join(str(group) for group in ext_data if group not in GREASE_TABLE)

        # EC Point Formats
        elif ext_type == 0x0b:  # 0x0b is the type for EC Point Formats
            # Assuming ext_data is the list of point formats
            elliptic_curve_point_format = "-".join(str(fmt) for fmt in ext_data if fmt not in GREASE_TABLE)

    # Remove trailing hyphen from extensions
    extensions = extensions.rstrip("-")

    # Construct JA3 string
    ja3 = f"{ssl_version},{cipher_suites},{extensions},{elliptic_curve},{elliptic_curve_point_format}"
    
    ja3_digest = create_ja3_digest(ja3)
    ja3_classification = ja3_tls_vals.get(ja3_digest)

    if ja3_classification:
        cur_client.tls_ja3_classifications.add(ja3_classification)
        pass

    if sni_list:
        cur_client.tls_snis.update(sni_list)
        pass

def create_ja3_digest(ja3_string: str) -> str:
    """
    Function to create the ja3 digest via md5.
    """
    return hashlib.md5(ja3_string.encode()).hexdigest()


def parse_supported_groups(data: bytes) -> List[int]:
    """Parse Supported Groups Extension"""
    length = struct.unpack('!H', data[:2])[0]
    groups = []
    for i in range(2, length + 2, 2):  # Step by 2 bytes for each group
        group = struct.unpack('!H', data[i:i+2])[0]
        groups.append(group)
    return groups

def parse_ec_point_formats(data: bytes) -> List[int]:
    """Parse Elliptic Curve Point Formats Extension"""
    length = data[0]
    formats = []
    for i in range(1, length + 1):  # Start at 1 to skip the length byte
        format = data[i]
        formats.append(format)
    return formats

def parse_tls_extensions(stream: BytesIO) -> list[TLSExtension]:
    """
    Function to parse TLS Extensions.
    """
    extensions_length = struct.unpack('!H', stream.read(2))[0]
    end = stream.tell() + extensions_length
    extensions = []

    while stream.tell() < end:
        ext_type, ext_length = struct.unpack('!HH', stream.read(4))
        ext_data = stream.read(ext_length)

        # Handle specific extensions
        if ext_type == 0x0a:  # Supported Groups Extension
            ext_data = parse_supported_groups(ext_data)
        elif ext_type == 0x0b:  # EC Point Formats Extension
            ext_data = parse_ec_point_formats(ext_data)

        extensions.append(TLSExtension(type_=ext_type, data=ext_data))

    if stream.tell() != end:
        raise ValueError("Extensions parsing did not consume the expected amount of bytes")

    return extensions

def parse_tls_payload(payload: bytes) -> TLSClientHello:
    """
    Function to parse a TLS payload. Does not support QUIC IETF.
    """
    if not payload:
        return None
    
    reader = BytesIO(payload)

    # Read the first byte for the type
    type_ =  struct.unpack('!B', reader.read(1))[0]

    # Ensure we have a ClientHello message
    if type_ != 0x16:  # 0x16 denotes Handshake
        # print(f'Not a handshake: {type(type_)} {type_}')
        return None

    # Skip the next two bytes
    tls_version = reader.read(2)

    # The next two bytes are the total length of the following TLS payload
    total_length = struct.unpack("!H", reader.read(2))[0]
    if len(reader.read()) < total_length:
        # print(f'Total length wrong: {total_length}')
        return None

    # Reset the stream position after the length check
    reader.seek(5)

    # Read the next byte for Handshake Type (ClientHello is 0x01)
    handshake_type = struct.unpack('!B', reader.read(1))[0]
    if handshake_type != TLS_CLIENT_HELLO:
        return None
    
    # length of the handshake message
    handshake_length = three_bytes_to_int(reader.read(3))
    if handshake_length < 0:
        return None

    # Next two bytes are TLS version again
    chello_version = reader.read(2)

    # Next 32 bytes are Random
    random = reader.read(32)

    # Session ID length (next byte)
    session_id_length = struct.unpack('!B', reader.read(1))[0]
    # Session ID
    session_id = reader.read(session_id_length)

    # Cipher Suites length (next two bytes)
    cipher_suites_length = struct.unpack("!H", reader.read(2))[0]
    # Cipher Suites (each cipher suite is 2 bytes)
    cipher_suites = []
    for _ in range(cipher_suites_length // 2):  # Divide by 2 because each cipher suite is 2 bytes
        cipher_suite = struct.unpack("!H", reader.read(2))[0]
        cipher_suites.append(cipher_suite)

    compression_methods_length = struct.unpack('!B', reader.read(1))[0]
    compression_methods = []
    for _ in range(compression_methods_length):
        compression_method = struct.unpack('!B', reader.read(1))[0]
        compression_methods.append(compression_method)

    extensions = parse_tls_extensions(reader)

    return TLSClientHello(type_, tls_version, chello_version, random, session_id, cipher_suites, compression_methods, extensions)
