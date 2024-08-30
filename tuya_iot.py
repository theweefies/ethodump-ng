#!/usr/bin/env python3

"""
Tuya IOT module for ethodump-ng.
"""

import json

def parse_tuya(payload: bytes, cur_client):

    # Parse the prefix
    prefix = payload[:16]
    first_part = prefix[:8]
    second_part = prefix[8:]

    # Identify the packet type and size
    packet_type = second_part[3]
    payload_size = second_part[7]

    # Parse suffix (if any)
    suffix = payload[16+payload_size-4:]

    # Extract the payload based on size
    payload = payload[16:16+payload_size-4]  # Exclude the suffix length
    payload_json = None

    # Try to decode JSON (if it's plaintext)
    try:
        payload_json = json.loads(payload.decode('utf-8','ignore'))
    except (UnicodeDecodeError, json.JSONDecodeError):
       pass
    
    if payload_json:
        with open(f"{cur_client.src_mac.replace(':','')}_tuya_iot.json", 'a') as fh:
            fh.write(payload_json + '\n')
    cur_client.protocols.add('TUYA_IOT')