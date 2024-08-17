#!/usr/bin/env python3

"""
DHIP (Dahua IP Protocol) module for ethodump-ng.
"""

import json
from globals import Client

dahuaProductDescriptions = {
    'DHI-NVR5416-4KS2':'Dahua 16 Channel 1.5U 4HDDs 4K & H.265 Pro Network Video Recorder',
    'DHI-NVR5432-4KS2':'Dahua 32 Channel 1.5U 4HDDs 4K & H.265 Pro Network Video Recorder',
    'DHI-NVR5464-4KS2':'Dahua 64 Channel 1.5U 4HDDs 4K & H.265 Pro Network Video Recorder',
    'DHIT-NVR5208-4KS2':'Dahua 8 Channel 1U 2HDDs 4K & H.265 Pro Network Video Recorder',
    'DHIT-NVR5216-4KS2':'Dahua 16 Channel 1U 2HDDs 4K & H.265 Pro Network Video Recorder',
    'DHIT-NVR5232-4KS2':'Dahua 32 Channel 1U 2HDDs 4K & H.265 Pro Network Video Recorder',
    'IPC-HDBW2431EP-S-S2':'Dahua 4MP Lite IR Fixed-focal Dome Network Camera',
    'DHT-IPC-HDBW2431EP-S-S2':'Dahua 4MP Lite IR Fixed-focal Dome Network Camera',
    'DH-IPC-HDBW5431EP-Z':'Dahua 4MP WDR IR Dome Network Camera',
    'IPC-HDBW5431EP-Z':'Dahua 4MP WDR IR Dome Network Camera',
    'IPC-HDW2431T-AS-S2':'Dahua 4MP Lite IR Fixed-focal Eyeball Network Camera',
    'IPC-HDW2439TP-AS-LED-S2':'Dahua 4MP Lite Full-color Fixed-focal Eyeball Network Camera',
    'DHT-IPC-HDW2439TP-AS-LED-S2':'Dahua 4MP Lite Full-color Fixed-focal Eyeball Network Camera',
    'IPC-HFW2439S-SA-LED-S2':'Dahua 4MP Lite Full-Color Fixed-focal Bullet Network Camera',
    'IPC-HFW2439SP-SA-LED-S2':'Dahua 4MP Lite Full-Color Fixed-focal Bullet Network Camera',
    'IPC-HFW2439MP-AS-LED-B-S2':'Dahua 4MP Lite Full-color Fixed-focal Bullet Network Camera',
    'DHT-IPC-HFW2831TP-AS-S2':'Dahua 8MP Lite IR Fixed-focal Bullet Network Camera',
    'IPC-HDW2431T-AS-S2I':'Dahua 4MP Lite IR Fixed-focal Eyeball Network Camera',
    'DH-IPC-HDW1531SP':'Dahua 5MP WDR HD IR Waterproof Eyeball Network Camera',
    'IPC-HDW1531SP':'Dahua 5MP WDR HD IR Waterproof Eyeball Network Camera',
    'DHT-IPC-HDW1439T1-LED-S4':'Dahua 4MP Entry Full-color Fixed-focal Eyeball Network Camera',
    'DHT-IPC-HDBW1431EP-S4':'Dahua 4MP Entry IR Fixed-focal Dome Network Camera',
    'DHT-IPC-HFW1431SP-S4':'Dahua 4MP WDR IR Mini-Bullet Camera',
    'DHT-IPC-HFW2439SP-SA-LED-S2':'Dahua 4MP Lite Full-color Fixed-focal Bullet Network Camera',
    'DHI-NVR5232-4KS2':'Dahua 32 Channel 1U 4K&H.265 Pro Network Video Recorder',
    'IPC-HFW2239SP-SA-LED-S2':'2MP Lite Full-color Fixed-focal Bullet Network Camera'
}

def parse_dhip(payload: bytes, cur_client: Client):
    if len(payload) < 32:
        return
    data = payload[32:-2]

    try:
        decoded_data = data.decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        return
    
    if 'mac' in decoded_data:
        try:
            dict_data = json.loads(decoded_data)
        except json.decoder.JSONDecodeError:
            return
        try:
            gateway = dict_data['params']['deviceInfo']['IPv4Address']['DefaultGateway']
            ipv4 = dict_data['params']['deviceInfo']['IPv4Address']['IPAddress']
            dev_type = dict_data['params']['deviceInfo']['DeviceType']
            dev_class = dict_data['params']['deviceInfo']['DeviceClass']
            mac = dict_data['mac']
            serial = dict_data['params']['deviceInfo']['SerialNo']
            httpport = str(dict_data['params']['deviceInfo']['HttpPort'])
            fw_version = dict_data['params']['deviceInfo']['Version']
            port = str(dict_data['params']['deviceInfo']['Port'])
        except KeyError as e:
            return
        
        dhip_dev = {}

        try:
            dhip_dev = {
                'Device Model':dev_type,
                'Device Class':dev_class,
                'Device Description':dahuaProductDescriptions[dev_type],
                'MAC':mac,
                'HTTP Port':httpport,
                'Serial Number':serial,
                'Firmware Version':fw_version,
                'Port':port
            }
        except KeyError as e:
            dhip_dev = {
                'Device Model':dev_type,
                'Device Class':dev_class,
                'Device Description':'No description available.',
                'MAC':mac,
                'HTTP Port':httpport,
                'Serial Number':serial,
                'Firmware Version':fw_version,
                'Port':port
            }
            pass
        if dhip_dev:
            cur_client.protocols.add('DHIP')
            cur_client.vendor_class = dhip_dev.get('Device Description')
            cur_client.connections = dhip_dev.get('Device Class')
            cur_client.oses.add(dhip_dev.get('Device Model'))
            cur_client.oses.add(dhip_dev.get('Serial Number'))
            cur_client.oses.add(dhip_dev.get('Firmware Version'))