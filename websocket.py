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
