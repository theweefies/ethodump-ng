#!/usr/bin/env python3

"""
TP-Link P2P module for ethodump-ng.
"""

import json
import binascii

from globals import Client, DARK_RED

def decrypt(data):
    key = 0xfa
    dec = ''
    for x in data[16:]:
        c = chr(key ^ x)
        key = x
        dec += c

    return dec

def parse_tp_link(packet: bytes, cur_client: Client):
    if not packet:
          return
    
    decrypted_data = None

    if packet[:2] == b'\x01\xf0':
        try:
            decrypted_data = decrypt(packet.replace(b'\n',b''))
        except binascii.Error as e:
            return
        
        if decrypted_data:

            if 'mac' in decrypted_data:
                try:
                    dict_data: dict = json.loads(decrypted_data)
                except json.decoder.JSONDecodeError as e:
                    return
                try:
                    method = dict_data.get('method', None)
                    data = dict_data.get('data', None)
                    if data:
                        group_id = data.get('group_id', None)
                        mac = data.get('mac', None)
                        if mac:
                            mac = mac.lower().replace('-',':')
                        ip = data.get('ip', None)
                        model = data.get('model', None)
                        operation_mode = data.get('operation_mode', None)
                        product_type = data.get('product_type', None)
                        bridge_mode = str(data.get('bridge_mode', None))
                        wpa3_support = str(data.get('wpa3_support', None))
                        onemesh_support = str(data.get('onemesh_support', None))
                        onemesh_role = data.get('onemesh_role', None)
                        onemesh_support_version = data.get('onemesh_support_version', None)
                except KeyError as e:
                    return
                
                tp_dev = {
                    'IP Address':ip if not None else '',
                    'Group ID':group_id if not None else '',
                    'Method':method if not None else '',
                    'Model':model if not None else '',
                    'Product Type':product_type if not None else '',
                    'Operation Mode':operation_mode if not None else '',
                    'Bridge Mode':bridge_mode if not None else '',
                    'WPA3 Support':wpa3_support if not None else '',
                    'OneMesh Support':onemesh_support if not None else '',
                    'OneMesh Role':onemesh_role if not None else '',
                    'OneMesh Support Version':onemesh_support_version if not None else ''
                }

                cur_client.protocols.add('TP-LINK P2P')
                cur_client.services.add('TP-Link P2P')
                if tp_dev['Model']:
                    cur_client.oses.add('mo: ' + tp_dev['Model'])
                if tp_dev['Operation Mode'] == 'RT':
                    cur_client.notes.add("router_mode")
                if tp_dev['WPA3 Support'] == True:
                    cur_client.notes.add("wpa3_support")
                if tp_dev['OneMesh Support'] == True:
                    cur_client.notes.add("mesh_support")
                if tp_dev.get('Bridge Mode'):
                    cur_client.notes.add("bridge_mode")
                if tp_dev['Product Type'] == 'WirelessRouter':
                    cur_client.notes.add('wireless_router')
                    cur_client.color = DARK_RED

                with open(f'{mac.replace(":","")}_tp-link.txt', 'w') as tpl_fh:
                    tpl_fh.write(f"MAC Address: {mac}\n")
                    tpl_fh.write("=========================================================\n")
                    tpl_fh.write(f'IP Address:         {tp_dev["IP Address"]}\n')
                    tpl_fh.write(f'Model:              {tp_dev["Model"]}\n')
                    tpl_fh.write(f'Product Type:       {tp_dev["Product Type"]}\n')
                    tpl_fh.write(f'Operation Mode:     {tp_dev["Operation Mode"]}\n')
                    tpl_fh.write(f'Bridge Mode:        {tp_dev["Bridge Mode"]}\n')
                    tpl_fh.write(f'WPA3 Support:       {tp_dev["WPA3 Support"]}\n')
                    tpl_fh.write(f'OneMesh Support:    {tp_dev["OneMesh Support"]}\n')
                    tpl_fh.write(f'OneMesh Role:       {tp_dev["OneMesh Role"]}\n')
                    tpl_fh.write(f'OneMesh Support     \n')
                    tpl_fh.write(f'Version(s):         {str(tp_dev["OneMesh Support Version"]).replace("[","").replace("]","")}\n')
                    tpl_fh.write(f'Group ID:           {tp_dev["Group ID"]}\n')
                    tpl_fh.write(f'Method:             {tp_dev["Method"]}\n')
                    tpl_fh.write('---------------------------------------------------------\n')

    elif packet[:2] == b"\x02\x00":
        json_string = packet[16:].decode('ascii')
        try:
            dict_obj = json.loads(json_string)
        except Exception as e:
            print(e)
            return
        params = dict_obj.get("params")
        if params:
            rsa_key = params.get("rsa_key")
            if rsa_key:
                with open(f"{cur_client.ip_address}_tp-link_rsa.pub",'w') as rsa_fh:
                    rsa_fh.write(rsa_key)
                cur_client.notes.add("tp_link_pubkey_found")