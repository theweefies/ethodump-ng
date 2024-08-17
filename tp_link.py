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
                    dict_data = json.loads(decrypted_data)
                except json.decoder.JSONDecodeError as e:
                    return
                try:
                    method = dict_data['method']
                    group_id = dict_data['data']['group_id']
                    mac = dict_data['data']['mac'].lower().replace('-',':')
                    ip = dict_data['data']['ip']
                    model = dict_data['data']['model']
                    operation_mode = dict_data['data']['operation_mode']
                    product_type = dict_data['data']['product_type']
                    bridge_mode = str(dict_data['data']['bridge_mode'])
                    wpa3_support = str(dict_data['data']['wpa3_support'])
                    onemesh_support = str(dict_data['data']['onemesh_support'])
                    onemesh_role = dict_data['data']['onemesh_role']
                    onemesh_support_version = dict_data['data']['onemesh_support_version']
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
                cur_client.oses.add(tp_dev['Model'])
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
