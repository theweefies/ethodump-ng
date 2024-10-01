#!/usr/bin/env python3

import socket
import struct
from io import BytesIO

from tcp_udp import checksum
from globals import ETH_HEADER_LEN, LLC_HEADER_LEN, Client
from globals import mac_address_to_bytes, bytes_to_mac

ETH_CDP           = b'\x20\x00'
CISCO_OUI         = b'\x00\x00\x0c'
CISCO_PID         = b'\x20\x00'

"""
Capabilities: 0x00000000
    .... .... .... .... .... .... .... ...0 = Router: No
    .... .... .... .... .... .... .... ..0. = Transparent Bridge: Yes
    .... .... .... .... .... .... .... .0.. = Source Route Bridge: No
    .... .... .... .... .... .... .... 0... = Switch: No
    .... .... .... .... .... .... ...0 .... = Host: No
    .... .... .... .... .... .... ..0. .... = IGMP capable: No
    .... .... .... .... .... .... .0.. .... = Repeater: No
    .... .... .... .... .... .... 0... .... = VoIP Phone: No
    .... .... .... .... .... ...0 .... .... = Remotely Managed Device: No
    .... .... .... .... .... ..0. .... .... = CVTA/STP Dispute Resolution/Cisco VT Camera: No
    .... .... .... .... .... .0.. .... .... = Two Port Mac Relay: No
"""

def parse_capabilities(capabilities_bytes):
    """
    Parse the CDP capabilities bitmap and return a list of capabilities that are enabled.
    
    :param capabilities_bytes: A 4-byte value representing the capabilities bitmap.
    :return: A list of strings representing the capabilities that are enabled.
    """
    # Convert the 4-byte value into an integer
    capabilities_int = struct.unpack("!I", capabilities_bytes)[0]

    # Map each bit to its corresponding capability
    capability_flags = [
        "Router",                                      # Bit 0
        "Transparent Bridge",                          # Bit 1
        "Source Route Bridge",                         # Bit 2
        "Switch",                                      # Bit 3
        "Host",                                        # Bit 4
        "IGMP capable",                                # Bit 5
        "Repeater",                                    # Bit 6
        "VoIP Phone",                                  # Bit 7
        "Remotely Managed Device",                     # Bit 8
        "CVTA/STP Dispute Resolution/Cisco VT Camera", # Bit 9
        "Two Port Mac Relay"                           # Bit 10
    ]

    enabled_capabilities = []

    # Check each bit in the integer and add the capability if the bit is set
    for i, capability in enumerate(capability_flags):
        if capabilities_int & (1 << i):  # Check if the i-th bit is set
            enabled_capabilities.append(capability)

    return enabled_capabilities

def parse_cdp_addresses_tag(tag_value: bytes):
    """
    Parse the CDP "Addresses" tag value which contains one or more addresses.
    
    :param tag_value: The raw byte data of the Addresses TLV value.
    :return: A list of parsed addresses, each containing the protocol and address.
    """
    offset = 0
    parsed_addresses = []
    
    # Extract the number of addresses (first 4 bytes)
    num_addresses = struct.unpack_from("!I", tag_value, offset)[0]
    offset += 4
    
    # Parse each address based on the number of addresses
    for _ in range(num_addresses):
        # Protocol type, length, and the actual protocol (3 bytes total)
        proto_type = struct.unpack_from("!B", tag_value, offset)[0]
        proto_len = struct.unpack_from("!B", tag_value, offset + 1)[0]
        protocol = struct.unpack_from("!B", tag_value, offset + 2)[0]
        offset += 3  # Move the offset past protocol info
        
        # Address length (2 bytes)
        address_len = struct.unpack_from("!H", tag_value, offset)[0]
        offset += 2
        
        # Address (address_len bytes)
        address_bytes = tag_value[offset:offset + address_len]
        offset += address_len
        
        # Handle different protocol types (currently handling only IP addresses)
        if protocol == 0xCC and address_len == 4:
            # IP address (IPv4, 4 bytes), convert to dotted decimal
            address = socket.inet_ntoa(address_bytes)
        else:
            # Non-IP address, store as raw bytes
            address = address_bytes.hex()  # Store as hex string for clarity
        
        # Store the parsed protocol and address in a dictionary
        parsed_addresses.append({
            "protocol_type": proto_type,
            "protocol_length": proto_len,
            "protocol": protocol,
            "address": address
        })
    
    return parsed_addresses

def parse_cdp_tlvs(packet_bytes: bytes):
    """
    Parse the TLVs from a Cisco Discovery Protocol packet.
    
    :param packet_bytes: The CDP packet starting from the TLV section.
    :return: A dictionary of parsed TLVs, where the key is the TLV type and the value is the TLV data.
    """
    offset = 0
    tlvs = {}

    # Continue until we process the entire packet
    while offset < len(packet_bytes):
        # Each TLV starts with 2 bytes for type and 2 bytes for length
        if len(packet_bytes[offset:]) < 4:
            break  # Not enough data to parse, so break out

        # Unpack the type (2 bytes) and length (2 bytes)
        tlv_type, tlv_length = struct.unpack_from("!HH", packet_bytes, offset)
        offset += 4  # Move the offset past type and length

        # Length includes the 4 bytes for the type and length fields themselves
        value_length = tlv_length - 4

        # Extract the value corresponding to the TLV
        tlv_value = packet_bytes[offset:offset + value_length]
        offset += value_length  # Move the offset past the TLV value

        # Store the parsed TLV in a dictionary
        tlvs[tlv_type] = tlv_value

        # If the length is zero or negative, break out of the loop to avoid infinite loops
        if tlv_length <= 0:
            break

    return tlvs

def parse_cdp_response(packet: bytes, cur_client: Client):
    """ Function to parse a CDP 802.3 Ethernet Frame. """

    offset = 0

    # Unpack Ethernet Header
    dst_mac, src_mac, length  = struct.unpack('!6s6sH', packet[offset: offset + ETH_HEADER_LEN])

    offset += ETH_HEADER_LEN

    src_mac = bytes_to_mac(src_mac)
    dst_mac = bytes_to_mac(dst_mac)

    if len(packet) < 22:
        return

    oui = packet[17:20]
    pid = packet[20:22]

    if oui != CISCO_OUI and pid != CISCO_PID:
        return
    
    cur_client.protocols.add('CDP')
    cur_client.services.add('Cisco')

    offset += LLC_HEADER_LEN

    if len(packet) < offset + 4: # if packet is too small for ETH + LLC + version + TTL + checksum stop
        return
    
    version, ttl, checksum = struct.unpack('!BBH', packet[offset : offset + 4])

    offset += 4

    tlvs = parse_cdp_tlvs(packet[offset:])

    for tag_id, tag_val in tlvs.items():
        if tag_id == 1:   # Device ID
            cur_client.hostnames.add(tag_val.decode())
        elif tag_id == 2: # Addresses
            addresses = parse_cdp_addresses_tag(tag_val)
            for address in addresses:
                for k, v in address.items():
                    if k == 'address':
                        note = f'tlv_address: {v}'
                        cur_client.notes.add(note)
        elif tag_id == 3: # Port ID
            note = f"port_id: {tag_val.decode()}"
            cur_client.notes.add(note)
        elif tag_id == 4: # Capabilities
            capes_list = parse_capabilities(tag_val)
            for cape in capes_list:
                cur_client.notes.add(cape.lower().replace(' ','_'))
        elif tag_id == 5: # Version String
            cur_client.oses.add(f'sv: {tag_val.decode()}')
        elif tag_id == 6: # Platform
            cur_client.oses.add(f'mo: {tag_val.decode()}')
