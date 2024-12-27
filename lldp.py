#!/usr/bin/env python3
"""
Module for Link-Layer Discovery Protocol for ethodump-ng
"""

import struct
from dataclasses import dataclass, field
from typing import List
from globals import bytes_to_ip, bytes_to_mac, Client
from io import BytesIO

@dataclass
class LLDPEntry:
    """
    Represents a single LLDP TLV entry.
    """
    type: int
    length: int
    value: bytes

    def parse_value(self):
        """
        Parse specific TLV value based on type.
        """
        if self.type == 1:  # Chassis ID
            return self.value.decode(errors='ignore')
        elif self.type == 2:  # Port ID
            return self.value.decode(errors='ignore')
        elif self.type == 3:  # TTL
            return struct.unpack('!H', self.value)[0]
        else:
            return self.value

@dataclass
class LLDP:
    """
    Represents a parsed LLDP packet.
    """
    mac: bytes
    entries: List[LLDPEntry] = field(default_factory=list)

def parse_lldp(sender_mac: str, reader: BytesIO) -> LLDP:
    """
    LLDP Parsing Function
    :param reader: BytesIO object containing LLDP data
    :return: LLDP object with parsed entries
    """
    lldp_packet = LLDP(mac=sender_mac)

    while True:
        # Read the type and length (2 bytes)
        try:
            tlv_header = reader.read(2)
            if len(tlv_header) < 2:
                break

            tlv_type_length = struct.unpack('!H', tlv_header)[0]
            tlv_type = (tlv_type_length >> 9) & 0x7F  # Extract type (7 bits)
            tlv_length = tlv_type_length & 0x1FF  # Extract length (9 bits)

            # Read the TLV value
            tlv_value = reader.read(tlv_length)
            if len(tlv_value) < tlv_length:
                break

            # Add parsed TLV entry
            entry = LLDPEntry(type=tlv_type, length=tlv_length, value=tlv_value)
            lldp_packet.entries.append(entry)

            # End of LLDPDU TLV (type 0)
            if tlv_type == 0:
                break

        except struct.error:
            break
    
    return lldp_packet

def process_lldp(lldp_packet: LLDP, clients: dict, flags) -> None:
    """
    Function to process LLDP packets and add client details
    """
    # Check if the sender is in the clients dictionary
    sender = None
    ip_address = None
    ext_client = None

    sender = clients.get(lldp_packet.mac)

    # If not, create a new Client instance and add it to the clients dictionary
    if not sender:
        sender = Client(lldp_packet.mac, flags.client_count)
        clients[lldp_packet.mac] = sender
        flags.client_count += 1
    else:
        if isinstance(sender, dict):

            for entry in lldp_packet.entries:
                if entry.type == 8: # Management Address
                    if entry.value[0] == 1: # IPv4 Address
                        ip_address = bytes_to_ip(entry.value[1:5])
                        break

            if ip_address:
                ext_client = sender.get(ip_address)
                if not ext_client:
                    clients[lldp_packet.mac][ip_address] = Client(lldp_packet.mac, flags.client_count)
                    sender = clients[lldp_packet.mac][ip_address]
                    flags.client_count += 1
                else:
                    sender = ext_client

    # Ensure final state is a valid Client object
    if not isinstance(sender, Client):
        return
    
    if ip_address:
        sender.ip_address = ip_address

    for entry in lldp_packet.entries:
        if entry.type == 4:                        # Port Description
            port_desc = entry.value.decode('ascii', 'ignore').strip('\00')
            sender.notes.add(f"port_description: {port_desc}")
        elif entry.type == 5:                      # System Name
            sender.oses.add(entry.value.decode('ascii', 'ignore').strip('\00'))
        elif entry.type == 6:                      # System Description
            sender.oses.add(entry.value.decode('ascii', 'ignore').strip('\00'))

    sender.protocols.add('LLDP')