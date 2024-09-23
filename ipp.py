#!/usr/bin/env python3

"""
IPP (print) module for ethodump-ng.
"""

def parse_ipp(payload: bytes, cur_client):

    with open(cur_client.src_mac.replace(':','') + '-printer.txt','w') as fh:
        fh.write(payload.decode('utf-8'))
    cur_client.protocols.add('IPP')
    cur_client.services.add('PRINTER')
    cur_client.notes.add('network_printer')
    ipp_str = None
    try:
        ipp_str = payload.decode('utf-8')
    except UnicodeDecodeError:
        return
    if ipp_str:
        lines = ipp_str.split('\r\n')
        for line in lines:
            try:
                key, val = line.split(' ', 1)
            except ValueError:
                continue
            val = val.replace('(','').replace(')','')
            if key == 'printer-make-and-model':
                cur_client.oses.add(val)
            elif key == 'printer-dns-sd-name':
                cur_client.hostnames.add(val)
            elif key == 'printer-uri':
                cur_client.resource_urls.add(val)
            elif key == 'printer-uri-supported':
                cur_client.resource_urls.add(val)
