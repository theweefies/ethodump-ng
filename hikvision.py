#!/usr/bin/env python3

"""
Hikvision module for ethodump-ng.
"""

import xml.etree.ElementTree as ET

hikvisionProductDescriptions = {
    'DS-2CV2Q21FD-IW':'HIKVISION 2 MP Indoor Audio Fixed PT Network Camera',
    'DS-2CD2T43G0-I5':'HIKVISION Pro-Series 4 MP Outdoor WDR Fixed Bullet Network Camera',
    'DS-2CD2T43G0-I8':'HIKVISION Pro-Series 4 MP Outdoor WDR Fixed Bullet Network Camera',
    'DS-2DE5432IW-AE':'HIKVISION Pro-Series PTZ 4 MP 32X Powered by DarkFighter IR Network Speed Dome',
    'DS-2DE4425IW-DE':'HIKVISION Pro-Series PTZ 4-inch 4 MP 25X Powered by DarkFighter IR Network Speed Dome'
    }

def create_dict_from_xml(xml_string):
    dictionary = {}
    for element in xml_string.iter():
        if element.text is not None and element.text.strip():
            dictionary[element.tag] = element.text.strip()
        else:
            try:
                if not isinstance(dictionary[element.tag], list):
                    dictionary[element.tag] = [dictionary[element.tag]]
                dictionary[element.tag].append(element.text.strip())
            except KeyError as e:
                continue
    return dictionary

def parseMalformedXML(string):
    
    device_data = {}
    xml_list = []
    field_list = ['Types','DeviceType','DeviceDescription','DeviceSN','CommandPort','HttpPort','MAC','IPv4Address','IPv4SubnetMask','IPv4Gateway',\
                 'IPv6Address','IPv6Gateway','IPv6MaskLen','DHCP','AnalogChannelNum','DigitalChannelNum','SoftwareVersion','DSPVersion',\
                 'BootTime','Encrypt','ResetAbility','DiskNumber','Activated','PasswordResetModeSecond','DetailOEMCode',\
                 'SupportSecurityQuestion','SupportHCPlatform','HCPlatformEnable','IsModifyVerificationCode','Salt','DeviceLock','SDKServerStatus',\
                 'SDKOverTLSServerStatus']
    xml_list = string.split('\r\n')
    for line in xml_list:
        if 'Uuid' in line:
            device_data['Uuid'] = line.replace('<ProbeMatch><Uuid>',"").replace('</Uuid>',"")
            continue
        if 'PasswordResetAbility' in line:
            device_data[field] = line.replace(f'<PasswordResetAbility>',"").replace(f'</PasswordResetAbility>',"")
            continue
        for field in field_list:
            if field in line:
                device_data[field] = line.replace(f'<{field}>',"").replace(f'</{field}>',"")

    return device_data

def parse_hikvision(payload: bytes, cur_client):
    
    try:
        xml_string = payload.decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        return
    
    if 'ProbeMatch' in xml_string or 'Hello' in xml_string or 'Probe' in xml_string:
        dict_data = None 
        try:
            root = ET.fromstring(xml_string)
            dict_data = create_dict_from_xml(root)
        except ET.ParseError as e:
            dict_data = parseMalformedXML(xml_string)
            pass

        if dict_data:
            cur_client.protocols.add('HIKVISION')
            gateway = dict_data.get('IPv4Gateway')
            dev_ipv4 = dict_data.get('IPv4Address')
            dev_desc = dict_data.get('DeviceDescription')
            prod_desc = hikvisionProductDescriptions.get('ProductDescription')
            mac = dict_data.get('MAC')
            dev_sn = dict_data.get('DeviceSN')
            command_port = dict_data.get('CommandPort')
            http_port = dict_data.get('HttpPort')
            dhcp = dict_data.get('DHCP')
            software_version = dict_data.get('SoftwareVersion')

            if dev_desc:
                cur_client.vendor_class = dev_desc
            if prod_desc:
                cur_client.oses.add('mo: ' + prod_desc)
            if dev_sn:
                cur_client.oses.add('sn: ' + dev_sn)
            if software_version:
                cur_client.oses.add('sv: ' + software_version)
            if dev_ipv4:
                cur_client.ip_address = dev_ipv4
            if dhcp:
                cur_client.notes.add('dhcp_on')