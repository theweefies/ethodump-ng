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
            dict_data: dict = json.loads(decoded_data)
        except json.decoder.JSONDecodeError:
            return

        dev_type = None
        dev_class = None
        ipv4_address = None
        serial = None
        httpport = None
        fw_version = None
        port = None
        gateway = None
        ipv4 = None
        try:
            params = dict_data.get('params', None)
            mac = dict_data.get('mac', None)
            if params:
                device_info = params.get('deviceInfo', None)
                if device_info:
                    dev_type = device_info.get('DeviceType', None)
                    dev_class = device_info.get('DeviceClass', None)
                    ipv4_address = device_info.get('IPv4Address', None)
                    serial = device_info.get('SerialNo', None)
                    httpport = str(device_info.get('HttpPort', None))
                    fw_version = device_info.get('Version', None)
                    port = str(device_info.get('Port', None))
                    if ipv4_address:
                        gateway = ipv4_address.get('DefaultGateway', None)
                        ipv4 = ipv4_address.get('IPAddress', None)
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
                'Port':port,
                'Gateway Address':gateway,
                'IPv4 Address':ipv4
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
                'Port':port,
                'Gateway Address':gateway,
                'IPv4 Address':ipv4
            }
            pass
        if dhip_dev:
            cur_client.protocols.add('DHIP')
            dev_desc = dhip_dev.get('Device Description', None)
            dev_class = dhip_dev.get('Device Class', None)
            dev_model = dhip_dev.get('Device Model', None)
            dev_sn = dhip_dev.get('Serial Number', None)
            dev_fw = dhip_dev.get('Firmware Version', None)
            dev_ipv4 = dhip_dev.get('IPv4 Address', None)
            if dev_fw:
                cur_client.oses.add('fw: ' + dev_fw)
            if dev_sn:
                cur_client.oses.add('sn: ' + dev_sn)
            if dev_model:
                cur_client.oses.add('mo: ' + dev_model)
                if 'IPC' in dev_model:
                    cur_client.services.add('Dahua IP Camera')
                    cur_client.notes.add('ip_camera')
                elif 'NVR' in dev_model:
                    cur_client.services.add('Dahua NVR')
                    cur_client.notes.add('network_video_recorder')
                elif 'DVR' in dev_model:
                    cur_client.services.add('Dahua DVR')
                    cur_client.notes.add('digital_video_recorder')
            cur_client.vendor_class = dev_desc
            cur_client.connections = dev_class
            if dev_ipv4:
                cur_client.ip_address = dev_ipv4
