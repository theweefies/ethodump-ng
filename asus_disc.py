#!/usr/bin/env python3

"""
ASUS Discovery Protocol Parser for ethodump-ng
"""

from globals import Client

ASUS_RESPONSE_BYTES = b"\x0c\x16\x1f"

def parse_asus_disc(data: bytes, cur_client: Client) -> None:
    """
    Parses the response from an asus discovery packet
    """

    if data[:3] == ASUS_RESPONSE_BYTES:
        
        # Offset values
        ssid_offset       = 0x80
        subnetmask_offset = 0xA8
        model_offset      = 0xC8
        firmware_offset   = 0xE8
        
        # Extract Router SSID (Plain-text string)
        ssid = data[ssid_offset:ssid_offset + 32].decode('ascii', errors='ignore').strip().replace("\00","")
        cur_client.notes.add(f'ssid: {ssid}')
        cur_client.notes.add('wireless_router')

        # Extract subnet mask Address (4 bytes)
        subnetmask = data[subnetmask_offset:subnetmask_offset + 32].decode('ascii', errors='ignore').strip().replace("\00","")
        cur_client.notes.add(f'subnet_mask: {subnetmask}')

        # Extract Router Model (Plain-text string)
        model = data[model_offset:model_offset + 32].decode('ascii', errors='ignore').strip().replace("\00","")
        cur_client.oses.add(f'mo: ASUS {model}')

        # Extract Router Model (Plain-text string)
        firmware = data[firmware_offset:firmware_offset + 16].decode('ascii', errors='ignore').strip().replace("\00","")
        cur_client.oses.add(f'fv: {firmware}')
