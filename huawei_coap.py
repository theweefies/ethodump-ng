#!/usr/bin/env python3

"""
Huawei COAP Discovery Protocol Parser for ethodump-ng
"""

import json

from globals import Client

HUAWEI_COAP_HEADER_BYTES = b"\x50\x02"

def parse_huawei_coap_packet(data: bytes, cur_client: Client) -> None:
    """
    Parses the response from an asus discovery packet
    """

    if data[:2] != HUAWEI_COAP_HEADER_BYTES:
        return None
    
    json_data = None

    try:
        json_data = json.loads(data[37:-1])
    except json.JSONDecodeError:
        return None

    if not json_data:
        return None

    
    
    dev_udid = json_data.get("deviceId")
    if dev_udid:
        try:
            udid_json_data = json.loads(dev_udid)
            dev_udid = udid_json_data.get("UDID")
        except json.JSONDecodeError:
            pass
        cur_client.notes.add(f"huawei_udid: {dev_udid}")

    dev_name = json_data.get("devicename")
    if dev_name:
        cur_client.oses.add(dev_name)
    
    hicom_version = json_data.get("hicomversion")
    if hicom_version:
        cur_client.notes.add(f"hicomversion: {hicom_version}")

    if not cur_client.ip_address:
        wlan_ip = json_data.get("wlanIp")
        cur_client.ip_address = wlan_ip
    
    b_data = json_data.get("bData")
    if b_data:
        try:
            b_data_json = json.loads(b_data)
            nickname = b_data_json.get("nickName")
            if nickname:
                cur_client.hostnames.add(nickname)
            else:
                cur_client.notes.add(f"b_data: {b_data}")
        except json.JSONDecodeError:
            cur_client.notes.add(f"b_data: {b_data}")
    
    coap_uri = json_data.get("coapUri")
    if coap_uri:
        cur_client.notes.add(f"coap_uri: {coap_uri}")

    with open(f"{cur_client.ip_address}_huawei_coap.json",'w') as h_fh:
        h_fh.write(f"{json_data}\n")
    
    return None