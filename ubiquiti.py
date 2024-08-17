#!/usr/bin/env python3

"""
Ubiquiti module for ethodump-ng.
"""

import struct
import binascii

from globals import Client, bytes_to_mac, bytes_to_ip

# frames with 02060 and a separator tag of 0b00 to start the payload
def ubi_tlv(length: int, payload: bytes):

    ubi_dev = {}
    cur_pos = 0

    while cur_pos < length:
        # Ensure we do not go out of bounds
        if cur_pos + 1 > length:
            break
        
        # Get the tag ID (1 byte)
        tag = payload[cur_pos]
        cur_pos += 1

        if cur_pos + 2 > length:
            break

        # Unpack the length (2 bytes)
        t_len = struct.unpack('!H', payload[cur_pos:cur_pos+2])[0]
        cur_pos += 2

        # bounds check
        if cur_pos + t_len > length:
            break
        
        if t_len != 0:

            # Extract the value based on t_len
            t_val = payload[cur_pos:cur_pos + t_len]
            ubi_dev[tag] = t_val
 
        # Move the current position by t_len
        cur_pos = cur_pos + t_len

    return ubi_dev

def parse_ubiquiti(packet: bytes, cur_client: Client):
    if not packet:
        return

    if len(packet) < 4:
        return
    
    # previously used a str comparison as well ('02060')
    ubi_dev = None

    if packet[:3] == b'\x01\x00\x00': # Ubiquiti Hello
        if packet[3] != 0: # 4th byte is length of the payload (not including itself)
            length = packet[3]
            payload = packet[4:4+length]
            if length != len(payload):
                return
            ubi_dev = ubi_tlv(length, payload)

    if ubi_dev:
        unknown_tags = []
        UNKNOWN_TAG = False
        cur_client.services.add('Ubiquity P2P')
        cur_client.protocols.add('UBI-P2P')
        for tag_id, val in ubi_dev.items():
            if tag_id == 1: # MAC Address
                if not cur_client.src_mac:
                    cur_client.src_mac = bytes_to_mac(val)
            elif tag_id == 2: # MAC Address & IP Address
                if not cur_client.src_mac and len(val) > 6:
                    cur_client.src_mac = bytes_to_mac(val[:6])
                if not cur_client.ip_address and len(val) >= 10:
                    cur_client.ip_address = bytes_to_ip(val[6:10])
            elif tag_id == 3: # Firmware Version
                cur_client.oses.add(val.decode('utf-8', 'ignore'))
            elif tag_id == 11: # Hostname
                cur_client.hostnames.add(val.decode('utf-8', 'ignore'))
            elif tag_id == 12: # Short Model
                cur_client.oses.add(val.decode('utf-8', 'ignore'))
            elif tag_id == 20: # Long Model
                cur_client.oses.add(val.decode('utf-8', 'ignore'))
            else:
                UNKNOWN_TAG = True
                unknown_tags.append(tag_id)

        if UNKNOWN_TAG:
            with open(f'{cur_client.src_mac.replace(":","")}-ubiquity-unknown-tags.txt', 'a') as f_ubi:
                for tag in unknown_tags:
                    f_ubi.write(f"Tag ID: {tag}\n")
                    f_ubi.write(f"Decoded Value: {ubi_dev[tag].decode('utf-8','ignore')}\n")
                    f_ubi.write(f"Hex Value: {binascii.hexlify(ubi_dev[tag])}\n\n")
