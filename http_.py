#!/usr/bin/env python3

"""
Module to handle HTTP packets for ethodump-ng.
"""
import re
import os
import datetime
import threading
import base64
import binascii
from urllib.parse import urlparse

from globals import grab_resource, GENERIC_UPNP_UA, check_make_path
from models import apple_models, banner_signatures

def detect_service_banner(payload: bytes | str, cur_client) -> None:
    """
    Function to check for service banners
    """
    def check_banner(payload:str):
        """
        Helper function to check if a banner patter matches the db
        """
        for service, patterns in banner_signatures.items():
            for pattern in patterns:
                if re.match(pattern, payload):
                    return payload.strip()  # Return the matched service name
        return None  # Return None if no pattern matches

    # Convert the byte payload to a string if it's in bytes
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', 'ignore')

    lines = re.split(r'\r?\n', payload)

    # Detect a payload with a banner + \r\n at the end and attempt to
    # determine the service from signatures
    if len(lines) == 2  and lines[1] == "":
        banner = check_banner(payload)
        if banner:
            cur_client.services.add(banner)

def decode_credentials(proxy_auth_header: str) -> str:
    """
    Function to decode credentials from Proxy-Authorization Header Element
    """
    auth_scheme, _, credentials = proxy_auth_header.partition(' ')
    decoded_credentials = credentials

    if auth_scheme.lower() == 'basic':
        try:
            decoded_credentials = base64.b64decode(credentials, validate=True).decode('utf-8')
        except (ValueError, binascii.Error):
            pass  # Fallback to raw credentials on error

        # For Bearer tokens
    elif auth_scheme.lower() == 'bearer':
        pass

    elif auth_scheme.lower() == 'digest':
        pass

        # NTLM credentials - Base64 encoded
    elif auth_scheme.lower() == 'ntlm':
        try:
            decoded_credentials = base64.b64decode(credentials, validate=True).decode('utf-8')
        except (ValueError, binascii.Error):
            pass

    return auth_scheme + " - " + decoded_credentials

def parse_http(payload: bytes | str, cur_client, lock: threading.Lock, resource_grab: bool=False) -> None:
    """
    Function to extract data from HTTP and perform resource grabs.
    """
    
    # Convert the byte payload to a string if it's in bytes
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', 'ignore')

    lines = re.split(r'\r?\n', payload)

    user_agent = None
    user_agent_model = None
    request_urn = None
    host_urn = None
    service = osys = model = None
    urn_prefix = 'http://'
    json_object = None
    form_encoded = None
    short_format_date_time = datetime.datetime.now().strftime('%m-%d-%Y-%H-%M')

    for line in lines:
        
        # Check for User-Agent and User-Agent Model
        if 'User-Agent:' in line:
            user_agent = line.split(':', 1)[1].strip()
        elif 'User-Agent Model:' in line:
            user_agent_model = line.split(':', 1)[1].strip()
        # Check for GET request URN containing 'zc?'
        # This has been seen in multiple devices that also advertise this
        # In MDNS traffic in TXT records as the URN for a service
        elif 'GET' in line and 'zc?' in line:
            request_urn = line.split(' ')[1]
        elif 'Host:' in line:
            host_urn = line.split(':', 1)[1].strip()
        elif 'Content-Type: application/json' in line:
            json_object = lines[-1]
        elif 'Content-Type: application/x-www-form-urlencoded' in line:
            form_encoded = lines[-1]
        elif 'Proxy-Authorization:' in line:
            proxy_creds = line.split(':', 1)[1].strip()
            creds = decode_credentials(proxy_creds)
            cur_client.cred_pairs.add(creds)

    # compile the resource URN so we can query for deets
    full_urn = (urn_prefix + host_urn + request_urn) if (host_urn and request_urn) else ""

    # Parse out details from User-Agent and User-Agent Model if present
    if user_agent:
        # Regex to parse out service, OS, and optionally model from User-Agent
        ua_regex = r'(?P<service>.+?)\/(?P<version>[\d\.]+) (?P<os>[^\/]+)\/(?P<os_version>[\d\.]+)(?: \((?P<model>[^\)]+)\))?'
        match = re.match(ua_regex, user_agent)
        if match:
            service = match.group('service')
            osys = f"{match.group('os')}/{match.group('os_version')}"
            model = match.group('model') if match.group('model') else user_agent_model

    if model:
        model_resolution = apple_models.get(model)
        if model_resolution:
            cur_client.oses.add(model_resolution)

    if service:
        cur_client.services.add(service)
    if osys:
        cur_client.oses.add(osys)
    if model:
        cur_client.oses.add(model)
    if user_agent:
        cur_client.user_agents.add(user_agent)
    
    if resource_grab and full_urn and full_urn not in cur_client.resource_urls:
        parsed_urn = urlparse(full_urn)
        if parsed_urn:
            grab_resource(full_urn, GENERIC_UPNP_UA, parsed_urn, lock)

    if full_urn:
        cur_client.resource_urls.add(full_urn)

    if json_object:
        file = check_make_path(cur_client.ip_address, f'json_object_{short_format_date_time}.json')
        with open(file, 'wb') as json_fh:
            json_fh.write(json_object)
    
    if form_encoded:
        file = check_make_path(cur_client.ip_address, f'form_encoded_{short_format_date_time}.encwww')
        with open(file, 'wb') as www_fh:
            www_fh.write(form_encoded)
    
