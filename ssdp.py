#!/usr/bin/env python3

from dataclasses import dataclass
import re
import urllib.request

from globals import Client
from models import upnp_useragent_patterns

NOTIFY = 'NOTIFY'
SEARCH = 'M-SEARCH'
UPNP_BASE_STRING = 'UPnP/1.0'

@dataclass
class SSDP:
    type_: str
    location: str
    server: str
    user_agent: str

def grab_resource(urn, user_agent, filename):
    """
    Fetches a resource from the specified URN using a custom User-Agent and saves it to a file.

    :param urn: The Uniform Resource Name (e.g., a URL) of the resource to fetch.
    :param user_agent: The custom User-Agent string to use for the request.
    :param filename: The name of the file where the resource will be saved.
    """
    # Create a request object with the custom User-Agent
    req = urllib.request.Request(urn, headers={'User-Agent': user_agent})

    # Perform the request
    with urllib.request.urlopen(req) as response:
        # Read the response
        content = response.read()

        # Save the content to a file
        with open(filename, 'wb') as f:
            f.write(content)

def parse_user_agent(user_agent):
    for pattern, device_type in upnp_useragent_patterns:
        match = re.search(pattern, user_agent)
        if match:
            # Extract data based on the named groups in the pattern
            for name, value in match.groupdict().items():
                if value:
                    return {name: value, "device_type": device_type}
            # If no named groups or values, return the device type
            return {"device_type": device_type}
    # Return None if no pattern matches
    return None

def parse_ssdp_packet(payload: bytes, cur_client: Client) -> None | SSDP:
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
            if 'LOCATION' in line:
                location = line.split(': ')[1].strip()
                if location:
                    cur_client.resource_urls.add(location)
            if 'SERVER' in line:
                server = line.split(': ')[1].strip()
                cur_client.user_agents.add(server)
                ua_parse_result = parse_user_agent(server)
                if ua_parse_result:
                    device_type = ua_parse_result.get('device_type')
                    if device_type:
                        cur_client.oses.add(device_type)
                else:
                    os_regex = r"([A-Za-z]+\/[\d\.]+)"
                    matches = re.findall(os_regex, server)
                    match = matches[0] if matches else None
                    if match and match != UPNP_BASE_STRING:
                        cur_client.oses.add(match)
                    else:
                        cur_client.oses.add(server)
            if 'USER-AGENT' in line:
                user_agent = line.split(': ')[1].strip()
                cur_client.user_agents.add(user_agent)

        return SSDP(type_, location, server, user_agent)
    else:
        return None
