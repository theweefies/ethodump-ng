#!/usr/bin/env python3

from dataclasses import dataclass
import re

from globals import Client

NOTIFY = 'NOTIFY'
SEARCH = 'M-SEARCH'

@dataclass
class SSDPNotify:
    type_: str
    location: str
    server: str

def parse_ssdp_packet(payload: bytes, cur_client: Client) -> None | SSDPNotify:
    """
    Function to parse SSDP Notify messages and extract resource
    urls and perform os detection.
    """
    type_ = None
    location = None
    server = None
    decoded_payload = payload.decode('utf-8','ignore')
    if NOTIFY in decoded_payload:
        type_ = NOTIFY
        lines = decoded_payload.split('\r\n')
        for line in lines:
            if 'LOCATION' in line:
                location = line.split(': ')[1].strip().replace('\r\n','')
                if location:
                    cur_client.resource_urls.add(location)
            if 'SERVER' in line:
                os_regex = r"([A-Za-z]+\/[\d\.]+)"
                matches = re.findall(os_regex, line)
                server = matches[0] if matches else None
                if server:
                    cur_client.oses.add(server)

        return SSDPNotify(type_, location, server)
    else:
        return None
