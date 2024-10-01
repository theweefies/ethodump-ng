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

class TLV():

    def __init__(self, tag, length, value):
        self.tag = tag
        self.length = length
        self.value = value

    @classmethod
    def parse(cls, stream):
        tag = stream[0]
        length = int.from_bytes(stream[1:3], 'big')
        value = stream[3:3+length]

        return cls(tag, length, value)

def parse_ubiquiti(packet: bytes, cur_client: Client):
    if not packet:
        return

    if len(packet) < 4:
        return
    
    unknown_tags = {}

    device = {'addresses':[]}

    # Skip first 4 bytes of packet
    pos = 4
    while pos != len(packet):
        tlv = TLV.parse(packet[pos:])
        pos += 3 + tlv.length

        if tlv.tag == 1:
            device['hwaddr'] = ':'.join(["{:02X}".format(x) for x in tlv.value])

        elif tlv.tag == 2:
            mac = ':'.join(["{:02X}".format(x) for x in tlv.value[:6]])
            ipv4 = '.'.join([str(x) for x in tlv.value[6:]])
            device['addresses'].append({"hwaddr":mac, "ipv4":ipv4})

        elif tlv.tag == 3:
            device['fwversion'] = tlv.value.decode()

        elif tlv.tag == 10:
            device['uptime'] = int.from_bytes(tlv.value, 'big')

        elif tlv.tag == 11:
            device['hostname'] = tlv.value.decode()

        elif tlv.tag == 12:
            device['board_shortname'] = tlv.value.decode()

        elif tlv.tag == 13:
            device['essid'] = tlv.value.decode()

        elif tlv.tag == 14:
            device['wmode'] = int.from_bytes(tlv.value, 'big')

        elif tlv.tag == 19:
            device['mac'] = ':'.join(["{:02X}".format(x) for x in tlv.value])

        elif tlv.tag == 20:
            device['product'] = tlv.value.decode()

        elif tlv.tag == 21:
            device['model'] = tlv.value.decode()

        elif tlv.tag == 22:
            device['software_version'] = tlv.value.decode()

        elif tlv.tag == 27:
            device['unknown_version'] = tlv.value.decode()
        else:
            unknown_tags[tlv.tag] = {"length":tlv.length, "value":tlv.value}

    if device['addresses']:
        cur_client.services.add('Ubiquity P2P')
        cur_client.protocols.add('UBI-P2P')

        if not cur_client.src_mac and 'hwaddr' in device:
            cur_client.src_mac = device['hwaddr']
        if not cur_client.ip_address:
            if 'ipv4' in device['addresses']:
                cur_client.ip_address = device['addresses']['ipv4']
        if 'fwversion' in device:
            cur_client.oses.add('fv: ' + device['fwversion'])
        if 'software_version' in device:
            cur_client.oses.add('sv: ' + device['software_version'])
        if 'hostname' in device:
            cur_client.hostnames.add(device['hostname'])
        if 'board_shortname' in device:
            cur_client.oses.add('mo: ' + device['board_shortname'])
        if 'product' in device:
            cur_client.oses.add('mo: ' + device['product'])
        if 'model' in device:
            cur_client.oses.add('mo: ' + device['model'])
        if 'essid' in device:
            cur_client.notes.add(f'essid: {device["essid"]}')
        if 'wmode' in device:
            cur_client.notes.add(f'wmode: {device["wmode"]}')

        with open(f'{cur_client.src_mac.replace(":","")}-ubiquity-device.txt', 'w') as f_ubi:
            f_ubi.write(device.__str__())
