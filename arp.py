#!/usr/bin/env python3


import struct
from dataclasses import dataclass
from globals import bytes_to_ip, bytes_to_mac, Client
from io import BytesIO

ARP_REQUEST = 1
ARP_REPLY = 2

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

def parse_arp(reader: BytesIO) -> ARP | None:
    """
    ARP Parsing Function
    """    
    data = reader.read(28)
    if len(data) < 28:
        return None
    
    hardware_type, protocol, hardware_size, protocol_size, opcode = struct.unpack('!HHBBH', data[:8])
    sender_mac, sender_ip, target_mac, target_ip = struct.unpack('!6s4s6s4s', data[8:])

    # Convert bytes to human-readable formats
    sender_mac = bytes_to_mac(sender_mac)
    sender_ip = bytes_to_ip(sender_ip)
    target_mac = bytes_to_mac(target_mac)
    target_ip = bytes_to_ip(target_ip)

    return ARP(hardware_type, protocol, hardware_size, protocol_size, \
               opcode, sender_mac, sender_ip, target_mac, target_ip)

def process_arp(arp_packet, clients, flags):
    # Check if the sender is in the clients dictionary
    sender = clients.get(arp_packet.sender_mac)

    # If not, create a new Client instance and add it to the clients dictionary
    if not sender:
        sender = Client(arp_packet.sender_mac, arp_packet.sender_ip)
        clients[arp_packet.sender_mac] = sender
    else:
        # If the sender is already known, update its IP address
        sender.ip_address = arp_packet.sender_ip

    # For ARP requests, check if the target is known and update or add it similarly
    if arp_packet.opcode == ARP_REQUEST and arp_packet.target_mac != '00:00:00:00:00:00':
        target = clients.get(arp_packet.target_mac)
        if not target:
            target = Client(arp_packet.target_mac, flags.client_count)  # Target IP might not be known from ARP request
            clients[arp_packet.target_mac] = target
            flags.client_count += 1
