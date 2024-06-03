#!/usr/bin/env python3

"""
Module to handle HTTP packets for ethodump-ng.
"""
import re
import datetime
import json
import threading
import base64
import binascii
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from globals import grab_resource, GENERIC_UPNP_UA, check_make_path, HOSTNAME
from models import apple_models, banner_signatures
from responses import spotify_get_response, final_spotify_post_response, youtube_get_response

def x_www_decode(payload: str):
    if not payload or type(payload) != str:
        return None
    
    if '&' not in payload or '=' not in payload:
        return None
    
    decoded_dict = {}
    pairs_list = payload.split('&')
    for pair in pairs_list:
        if len(pair.split('=')) < 2:
            continue
        key, val = pair.split('=')
        decoded_dict[key] = val

    return decoded_dict

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

def parse_http(payload: bytes | str, cur_client, resource_grab: bool=False) -> None:
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
    xml_object = None
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
        elif 'Content-Type: text/xml' in line:
            xml_object = payload
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
            grab_resource(full_urn, GENERIC_UPNP_UA, parsed_urn)

    if full_urn:
        cur_client.resource_urls.add(full_urn)

    if json_object:
        file = check_make_path(cur_client.ip_address, f'json_object_{short_format_date_time}.json')
        with open(file, 'wb') as json_fh:
            json_fh.write(json_object.encode())
    
    if form_encoded:
        file = check_make_path(cur_client.ip_address, f'form_encoded_{short_format_date_time}.encwww')
        with open(file, 'wb') as www_fh:
            www_fh.write(form_encoded.encode())

    if xml_object:
        file = check_make_path(cur_client.ip_address, f'xml_object_{short_format_date_time}.xml')
        with open(file, 'wb') as xml_fh:
            xml_fh.write(xml_object.encode())
    
class HTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "Sony-Linux/4.1, UPnP/1.0, Sony_UPnP_SDK/1.0"

    def __init__(self, *args, allowed_ip=None, hostname=HOSTNAME, redirect_path=None, **kwargs):
        self.allowed_ip = allowed_ip
        self.hostname = hostname
        self.redirect_path = redirect_path
        super().__init__(*args, **kwargs)

    def version_string(self):
        """Override the version_string method to control the Server header"""
        return self.server_version

    def do_GET(self):
        if self.allowed_ip and self.client_address[0] != self.allowed_ip:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Access denied")
            return
        user_agent = None    
        # Log request details
        print(f"\nReceived GET request from {self.client_address}")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        for type_,val in self.headers.items():
            if 'User-Agent' in type_:
                user_agent = val
        if self.redirect_path in self.path:
            self.serve_resource("GET", user_agent)

    def do_POST(self):
        if self.allowed_ip and self.client_address[0] != self.allowed_ip:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Access denied")
            return
        user_agent = None
        # Log request details
        print(f"\nReceived POST request from {self.client_address}")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        for type_,val in self.headers.items():
            if 'User-Agent' in type_:
                user_agent = val
        # Get the length of the data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        # handle the payload
        payload = post_data.decode('utf-8')
        print(f"Payload:\n{payload}")
        decoded_dict = x_www_decode(payload)
        client_key = decoded_dict.get("clientKey")
        if not client_key:
            flag = 'clientKey-invalid'
        else:
            flag = 'clientKey-valid'

        self.serve_resource("POST", user_agent, flag)

    def serve_resource(self, http_type, user_agent, flag=None):
        if not user_agent:
            return
        if 'Spotify' in user_agent:
            if http_type == 'GET':
                spotify_get_response["remoteName"] = self.hostname
                content = json.dumps(spotify_get_response)
            elif http_type == 'POST' and flag:
                content = json.dumps(final_spotify_post_response)
                # if flag == 'clientKey-invalid':
                #    content = json.dumps(spotify_post_response)
                # elif flag == 'clientKey-valid':
                #    content = json.dumps(final_spotify_post_response)
        elif 'youtube' in user_agent:
            if http_type == 'GET':
                content = youtube_get_response
        else:
            content = ""
            
        self.send_response(200)
        if 'Spotify' in user_agent:
            self.send_header("Content-type", "application/json")
        elif 'youtube' in user_agent:
            self.send_header("Content-type", "text/xml")
        #self.send_header("Content-Security-Policy", "frame-ancestors 'none';")
        self.send_header("Server", "eSDK")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def log_message(self, format: str, *args) -> None:
        return #super().log_message(format, *args)

def create_request_handler_class(allowed_ip, hostname, redirect_path):
    class CustomHTTPRequestHandler(HTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, allowed_ip=allowed_ip, hostname=hostname, redirect_path=redirect_path, **kwargs)
    return CustomHTTPRequestHandler

def start_server(red_obj):
    """
    Threaded function to initialize a custom http server.
    """
    allowed_ip = red_obj.target_ip
    ip_address = red_obj.redirect_ip
    port = red_obj.redirect_port
    hostname = red_obj.hostname
    redirect_path = red_obj.redirect_path

    server_class = HTTPServer
    handler_class = create_request_handler_class(allowed_ip, hostname, redirect_path)
    server_address = (ip_address, port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
