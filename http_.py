#!/usr/bin/env python3

"""
Module to handle HTTP packets for ethodump-ng.
"""
import re
import ssl
import time
import datetime
import json
import logging
import socket
import base64
import binascii
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPMessage, parse_headers

from globals import (grab_resource, GENERIC_UPNP_UA, check_make_path, 
                     HOSTNAME, UUID_K, LONG_VERSION, PK, MODEL_NAME, BASE32)
from models import apple_models, banner_signatures
from responses import (spotify_get_response, final_spotify_post_response,
    youtube_get_response_init, chromecast_device_desc_xml, youtube_get_response_webserver_stopped,
    youtube_get_response_webserver_running, youtube_get_response_webserver_session_established,
    youtube_get_response_webserver_prober_id, youtube_get_response_webserver_auth)

logging.basicConfig(level=logging.DEBUG)

SESSION_NONE        = 0
SESSION_STOPPED     = 1
SESSION_RUNNING     = 2
SESSION_ESTABLISHED = 3
SESSION_PROBE       = 4
SESSION_AUTH        = 5
SESSION_IDLE        = 6
SESSION_STATE = SESSION_NONE

post_preserve = {}

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

def detect_tls_client_hello(connection):
    try:
        initial_data = connection.recv(5, socket.MSG_PEEK)
        if len(initial_data) < 5:
            return False
        if initial_data[0] == 0x16 and initial_data[1] == 0x03:
            return True
    except Exception as e:
        print(f"Error detecting TLS Client Hello: {e}")
    return False

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
            cur_client.oses.add('mo: ' + model_resolution)

    if service:
        cur_client.services.add(service)
    if osys:
        cur_client.oses.add('os: ' + osys)
    if model:
        cur_client.oses.add('mo:' + model)
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
    server_version = "SHP, UPnP/1.0, Sony UPnP SDK/1.0"
    user_agent = "DLNADOC/1.50 SEC_HHP_"

    def __init__(self, *args, red_obj, **kwargs):
        self.allowed_ip = red_obj.target_ip
        self.hostname = red_obj.hostname
        self.redirect_path = red_obj.redirect_path
        self.server_ip = red_obj.redirect_ip
        self.port = red_obj.redirect_port
        self.https_port = red_obj.redirect_port_https
        self.user_agent = f"DLNADOC/1.50 SEC_HHP_{self.hostname}"
        
        super().__init__(*args, **kwargs)

    def version_string(self):
        """Override the version_string method to control the Server header"""
        return self.server_version

    def do_GET(self):
        global SESSION_STATE
        headers = {}
        if self.allowed_ip and self.client_address[0] != self.allowed_ip:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Access denied")
            return    
        # Log request details
        print(f"\nReceived GET request from {self.client_address}")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        for type_,val in self.headers.items():
            headers[type_] = val
        if self.redirect_path in self.path:
            self.serve_resource("GET", headers, flag=None)
        elif '/ws/app' in self.path:
            if SESSION_STATE == SESSION_NONE:
                self.serve_resource("GET", headers, flag=None)
                SESSION_STATE = SESSION_STOPPED
            elif SESSION_STATE == SESSION_STOPPED:
                self.serve_resource("GET", headers, flag=SESSION_STOPPED)
                SESSION_STATE = SESSION_RUNNING
            elif SESSION_STATE == SESSION_RUNNING:
                self.serve_resource("GET", headers, flag=SESSION_RUNNING)
                SESSION_STATE = SESSION_ESTABLISHED
            elif SESSION_STATE == SESSION_ESTABLISHED:
                self.serve_resource("GET", headers, flag=SESSION_ESTABLISHED)
                SESSION_STATE = SESSION_PROBE
            elif SESSION_STATE == SESSION_PROBE:
                self.serve_resource("GET", headers, flag=SESSION_PROBE)
                SESSION_STATE = SESSION_AUTH
            elif SESSION_STATE == SESSION_AUTH:
                self.serve_resource("GET", headers, flag=SESSION_AUTH)
                SESSION_STATE = SESSION_IDLE
            else:
                self.serve_resource("GET", headers, flag=SESSION_ESTABLISHED)
            
        else:
            return

    def do_POST(self):
        global SESSION_STATE, post_preserve
        headers = {}
        flag = None
        if self.allowed_ip and self.client_address[0] != self.allowed_ip:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Access denied")
            return
        # Log request details
        print(f"\nReceived POST request from {self.client_address}")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        for type_,val in self.headers.items():
            headers[type_] = val
        # Get the length of the data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        # handle the payload
        payload = post_data.decode('utf-8')
        print(f"Payload:\n{payload}")
        decoded_dict = x_www_decode(payload)
        user_agent = headers.get('User-Agent')
        
        if user_agent:
            if 'spotify' in user_agent.lower():
                client_key = decoded_dict.get("clientKey")
                if not client_key:
                    flag = 'clientKey-invalid'
                else:
                    flag = 'clientKey-valid'
            if 'youtube' in user_agent.lower():
                SESSION_STATE = SESSION_RUNNING
                flag = post_preserve = decoded_dict

        self.serve_resource("POST", headers, flag)

    def serve_resource(self, http_type, headers: dict, flag=None):
        global post_preserve
        user_agent = headers.get('User-Agent')
        content_type = headers.get('Content-Type')
        accept_language = headers.get('Accept-Language')
        origin = headers.get('Origin')

        timenow = time.gmtime()
        # Format the current time to the specified format
        formatted_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", timenow)
        
        if not user_agent:
            return
        
        # Content control block
        if 'spotify' in user_agent.lower():
            if http_type == 'GET':
                spotify_get_response["remoteName"] = self.hostname
                content = json.dumps(spotify_get_response)
            elif http_type == 'POST' and flag:
                content = json.dumps(final_spotify_post_response)
                # if flag == 'clientKey-invalid':
                #    content = json.dumps(spotify_post_response)
                # elif flag == 'clientKey-valid':
                #    content = json.dumps(final_spotify_post_response)
        elif 'youtube' in user_agent.lower():
            if http_type == "GET" and not flag:
                content = youtube_get_response_init.format(
                    self.hostname, MODEL_NAME, LONG_VERSION, UUID_K, PK, self.port
                    )
                #content = chromecast_device_desc_xml.format(self.server_ip, self.https_port, self.hostname, UUID_K)
            elif http_type == "GET" and flag == SESSION_STOPPED:
                content = youtube_get_response_webserver_stopped
            elif http_type == "GET" and flag == SESSION_RUNNING:
                content = youtube_get_response_webserver_running
            elif http_type == "GET" and flag == SESSION_ESTABLISHED:
                theme = post_preserve.get('theme')
                content = youtube_get_response_webserver_session_established.format(
                    MODEL_NAME, BASE32, theme if theme else 'cl', PK, UUID_K
                    )
            elif http_type == "GET" and flag in [SESSION_PROBE,SESSION_IDLE]:
                theme = post_preserve.get('theme')
                content = youtube_get_response_webserver_prober_id.format(
                    MODEL_NAME, BASE32, theme if theme else 'cl', PK, UUID_K, UUID_K.upper()
                    )
            elif http_type == "GET" and flag == SESSION_AUTH:
                theme = post_preserve.get('theme')
                content = youtube_get_response_webserver_auth.format(
                    MODEL_NAME, BASE32, theme if theme else 'cl', PK, UUID_K, UUID_K.upper()
                    )
            elif http_type == "POST":
                content = f'http://{self.server_ip}:{self.port}/ws/apps/YouTube/run'
        else:
            content = chromecast_device_desc_xml.format(self.server_ip, self.https_port, self.hostname, UUID_K)

        # Header composition block 
        
        if 'spotify' in user_agent.lower():
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", len(content))
            self.send_header("Server", "eSDK")
            self.send_header("Connection", "keep-alive")
            #self.send_header("Content-Security-Policy", "frame-ancestors 'none';")
        elif 'youtube' in user_agent.lower():
            if http_type == 'POST':
                self.send_response(201,"Created")
            else:
                self.send_response(200)
            if not flag:
                self.send_header("Content-Language", "en-US,en;q=0.9")
            else:
                self.send_header("API-Version", "v1.00")
            if http_type == 'POST':
                self.send_header("Content-type", "text/html")
                self.send_header("LOCATION", f'http://{self.server_ip}:{self.port}/ws/apps/YouTube/run')
            else:
                self.send_header("Content-type", 'text/xml; charset="utf-8"')
            
            if flag:
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
            
            self.send_header("Content-Length", len(content))
            
            if not flag:
                self.send_header("Connection", "close")
                self.send_header("User-Agent", self.user_agent)
                self.send_header("Application-URL", f"http://{self.server_ip}:{self.port}/ws/app/")

            if origin and not flag:
                self.send_header("Access-Control-Allow-Origin", origin)

            if flag:
                self.send_header("Date", formatted_time)
                self.send_header("Server", "WebServer")
        else:
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-Length", len(content))
            self.send_header("Connection", "close")
            self.send_header("User-Agent", self.user_agent)
        
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def log_message(self, format: str, *args) -> None:
        return #super().log_message(format, *args)
    
    def handle_one_request(self):
        """
        Handle a single HTTP request, overridden to 
        support RTSP and TLS detection and redirection. """
        try:
            #server_ip, port = self.server.server_address
            # Detect TLS Client Hello
            if detect_tls_client_hello(self.connection):
                self.requestline = 'TLS Client Hello detected'
                self.request_version = 'TLS'
                if self.https_port: 
                    self.command = 'TLS Redirect'
                    self.send_response(200)
                    self.send_header('Connecton', 'close')
                    self.send_header('Content-Length','0')
                    self.send_header('X-TLS-Port', f'{self.https_port}')
                    self.end_headers()
                    self.close_connection = True
                    return
                else:
                    return
                    self.command = 'HTTP Only'
                    self.send_response(200)
                    self.send_header('Set-Cookie', 'sessionId=abc123; HttpOnly; Secure')
                    self.send_header('Content-Length','0')
                    self.end_headers()
                    self.close_connection = True
                    return

            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            
            if not self.raw_requestline:
                self.close_connection = True
                return
            
            if not self.parse_request():
                return
            
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.send_error(501, "Unsupported method (%r)" % self.command)
                return
            
            method = getattr(self, mname)
            method()
            self.wfile.flush()  # Actually send the response if not already done.
        except ConnectionResetError:
            self.close_connection = True
    
    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.
        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            [command, path, version] = words
            if version.startswith('HTTP/'):
                self.request_version = version
            elif version.startswith('RTSP/'):
                self.request_version = version
            else:
                self.send_error(400, "Bad request version (%r)" % version)
                return False
        elif len(words) == 2:
            [command, path] = words
            self.close_connection = False
            if command != 'GET':
                self.send_error(400, "Bad HTTP/0.9 request type (%r)" % command)
                return False
        else:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False
        
        self.command, self.path = command, path

        # Parse headers from the file
        self.headers = parse_headers(self.rfile)
        
        if self.headers.get('Expect', '') == '100-continue':
            if not self.handle_expect_100():
                return False

        if self.protocol_version >= "HTTP/1.1":
            self.close_connection = self.headers.get('Connection', '').lower() == 'close'
        return True

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Hello, secure world!')

def create_request_handler_class(red_obj):
    class CustomHTTPRequestHandler(HTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, red_obj=red_obj, **kwargs)
    return CustomHTTPRequestHandler

def create_ssl_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1 if not needed
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.set_ciphers("ECDHE+AESGCM")
    return context

def start_server(red_obj):
    """
    Threaded function to initialize a custom http server.
    """
    try:
        ip_address = red_obj.redirect_ip
        port = red_obj.redirect_port

        server_class = HTTPServer
        handler_class = create_request_handler_class(red_obj)
        server_address = (ip_address, port)
        httpd = server_class(server_address, handler_class)
        httpd.serve_forever()
    except OSError:
        print('[!] ERROR: Failed to start HTTP server.')
        return

def start_https_server(red_obj):
    """
    Threaded function to initialize a custom https server.
    """
    try:
        ip_address = red_obj.redirect_ip
        port = red_obj.redirect_port_https

        # Paths to your certificate and key files
        cert_file = red_obj.cert_file
        key_file = red_obj.key_file

        server_class = HTTPServer
        # handler_class = create_request_handler_class(allowed_ip, hostname, redirect_path)
        server_address = (ip_address, port)
        https_d = server_class(server_address, SimpleHTTPRequestHandler)# handler_class)
        # Wrap the HTTP server socket with SSL
        # Create SSL context
        context = create_ssl_context(cert_file, key_file)

        # Wrap the server socket with SSL
        https_d.socket = context.wrap_socket(https_d.socket, server_side=True, 
                                do_handshake_on_connect=True,
                                suppress_ragged_eofs=True,)
        print(f"Serving HTTPS on port {port}")
        https_d.serve_forever()
    except OSError as e:
        print(f'[!] ERROR: Failed to start HTTPS server: {e}')
        return
    except ssl.SSLError as e:
        print(f'[!] SSL ERROR: {e}')
    except Exception as e:
        print(f'[!] ERROR: {e}')