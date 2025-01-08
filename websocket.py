#!/usr/bin/env python3

"""
Websocket module for ethodump-ng.
"""

import json
from urllib.parse import urlparse

from globals import grab_resource, GENERIC_UPNP_UA

def parse_websocket_api(payload: bytes, cur_client, grab_resources: bool):
    """
    Parse a pure json payload.
    """

    payload = b"\x7b\x22\x64\x61\x74\x61\x22\x3a\x7b\x22\x76\x31\x22\x3a\x7b\x22"\
b"\x75\x72\x69\x22\x3a\x22\x68\x74\x74\x70\x3a\x2f\x2f\x31\x39\x32"\
b"\x2e\x31\x36\x38\x2e\x36\x38\x2e\x31\x30\x33\x3a\x38\x30\x30\x31"\
b"\x2f\x6d\x73\x2f\x31\x2e\x30\x2f\x22\x7d\x2c\x22\x76\x32\x22\x3a"\
b"\x7b\x22\x75\x72\x69\x22\x3a\x22\x68\x74\x74\x70\x3a\x2f\x2f\x31"\
b"\x39\x32\x2e\x31\x36\x38\x2e\x36\x38\x2e\x31\x30\x33\x3a\x38\x30"\
b"\x30\x31\x2f\x61\x70\x69\x2f\x76\x32\x2f\x22\x7d\x7d\x2c\x22\x72"\
b"\x65\x6d\x6f\x74\x65\x22\x3a\x22\x31\x2e\x30\x22\x2c\x22\x73\x69"\
b"\x64\x22\x3a\x22\x75\x75\x69\x64\x3a\x62\x31\x34\x31\x34\x33\x33"\
b"\x34\x2d\x36\x34\x63\x31\x2d\x34\x32\x66\x37\x2d\x39\x63\x62\x65"\
b"\x2d\x31\x35\x35\x63\x31\x32\x61\x36\x30\x34\x31\x63\x22\x2c\x22"\
b"\x74\x74\x6c\x22\x3a\x38\x30\x30\x30\x2c\x22\x74\x79\x70\x65\x22"\
b"\x3a\x22\x61\x6c\x69\x76\x65\x22\x7d\x0a"


    payload_json = None
    api_response = None
    json_res     = None

    # Try to decode JSON
    try:
        payload_json = json.loads(payload.decode('utf-8','ignore'))
    except (UnicodeDecodeError, json.JSONDecodeError):
       pass
    
    if payload_json:
        with open(f"{cur_client.src_mac.replace(':','')}_websocket.json", 'a') as fh:
            fh.write(str(payload_json) + '\n')

        data = payload_json.get("data")
        if data:
            for version, val in data.items():
                if isinstance(val, dict):
                    uri = val.get('uri')
                    if uri and grab_resources and uri not in cur_client.resource_urls:
                        parsed_urn = urlparse(uri)
                        api_response = grab_resource(uri, GENERIC_UPNP_UA, parsed_urn)
                        cur_client.resource_urls.add(uri)

    cur_client.protocols.add('WEBSOCKET API')

    if api_response:
        
        try:
            json_res = json.loads(api_response.decode('utf-8','ignore'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

        if json_res:
            with open(f"{cur_client.src_mac.replace(':','')}_websocket_response.json", 'a') as fh:
                fh.write(str(json_res) + '\n')

            device = json_res.get("device")
            if device:
                os         = device.get("OS")
                if os:
                    cur_client.oses.add(os)
                desc       = device.get("description")
                if desc:
                    cur_client.notes.add(f"description: {desc}")
                firmware   = device.get("firmwareVersion") 
                if firmware:
                    cur_client.oses.add(f"fv: {firmware}")
                model      = device.get("model")
                if model:
                    cur_client.oses.add(f"mo: {model}")
                model_name = device.get("modelName")
                if model_name:
                    cur_client.oses.add(f"mn: {model_name}")
                hostname   = device.get("name")
                if hostname:
                    cur_client.hostnames.add(hostname)
                conn_ap    = device.get("ssid")
                if conn_ap:
                    cur_client.connections.add(f"ConnectedAP: {conn_ap}")
                type_      = device.get("type")
                if type_:
                    cur_client.notes.add(f"type: {type_}")
                

"""class Client:
    protocols     = set([])
    src_mac       = "11:11:11:11:11:11"
    resource_urls = set([])
    notes         = set([])
    oses          = set([])
    connections   = set([])
    hostnames     = set([])

client = Client()

parse_websocket_api(None, client, True)"""