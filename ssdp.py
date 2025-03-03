#!/usr/bin/env python3

from dataclasses import dataclass
import re
from urllib.parse import urlparse
from globals import Client, grab_resource, GENERIC_UPNP_UA
from models import upnp_useragent_patterns

NOTIFY               = 'NOTIFY'
SEARCH               = 'M-SEARCH'
UPNP_BASE_STRING     = 'UPnP/1.0'
UPNP_1_1_BASE_STRING = 'UPnP/1.1'

LOCATION_TAG         = 'LOCATION:'
SERVER_TAG           = 'SERVER:'
USER_AGENT_TAG       = 'USER-AGENT'

DEVICE_TYPE_KEY      = "device_type"

HTTP_NO_HOST         = 'http://:'
HTTPS_NO_HOST        = 'https://:'

@dataclass
class SSDP:
    type_: str
    location: str
    server: str
    user_agent: str

def parse_user_agent(user_agent):
    for pattern, device_type in upnp_useragent_patterns:
        match = re.search(pattern, user_agent)
        if match:
            # Extract data based on the named groups in the pattern
            for name, value in match.groupdict().items():
                if value:
                    return {name: value, DEVICE_TYPE_KEY: device_type}
            # If no named groups or values, return the device type
            return {DEVICE_TYPE_KEY: device_type}
    # Return None if no pattern matches
    return None

def parse_ssdp_packet(payload: bytes, cur_client: Client, grab_resources: bool=False): # -> None | SSDP:
    """
    Function to parse SSDP Notify messages and extract resource
    urls and perform os detection.
    """
    if not payload:
        return None
    
    type_ = None
    location = None
    server = None
    decoded_payload = payload.decode('utf-8','ignore')
    if NOTIFY in decoded_payload or SEARCH in decoded_payload:
        if NOTIFY in decoded_payload:
            type_ = NOTIFY
        elif SEARCH in decoded_payload:
            type_ = SEARCH
        else:
            return None

        lines = decoded_payload.split('\r\n')
        user_agent = ""
        location = ""
        server = ""
        for line in lines:
            if LOCATION_TAG in line:
                location = line.split(': ')[1].strip()
                if location:
                    if grab_resources and location not in cur_client.resource_urls:
                            parsed_urn = urlparse(location)
                            if parsed_urn:
                                grab_resource(location, GENERIC_UPNP_UA, parsed_urn)
                    if HTTP_NO_HOST in location or HTTPS_NO_HOST in location:
                        prefix, suffix = location.split('//')
                        location = f"{prefix}//{cur_client.ip_address}{suffix}"
                    cur_client.resource_urls.add(location)
            if SERVER_TAG in line:
                server = line.split(': ')[1].strip()
                cur_client.user_agents.add(server)
                ua_parse_result = parse_user_agent(server)
                if ua_parse_result:
                    device_type = ua_parse_result.get(DEVICE_TYPE_KEY)
                    if device_type:
                        cur_client.oses.add('dt: ' + device_type)
                else:
                    os_regex = r"([A-Za-z]+\/[\d\.]+)"
                    matches = re.findall(os_regex, server)
                    match = matches[0] if matches else None
                    if match and match not in [UPNP_BASE_STRING, UPNP_1_1_BASE_STRING]:
                        cur_client.oses.add('os: ' + match)
                    elif match and match in [UPNP_BASE_STRING, UPNP_1_1_BASE_STRING]:
                        cur_client.services.add(match)
                    else:
                        cur_client.oses.add('upnp: ' + server)
            if USER_AGENT_TAG in line:
                user_agent = line.split(': ')[1].strip()
                cur_client.user_agents.add(user_agent)

        return SSDP(type_, location, server, user_agent)
    else:
        return None
