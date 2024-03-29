#!/usr/bin/env python3

import socket

oui_table = {}
oui_file = "oui.csv"

def bytes_to_mac(bytes):
    """
    Converts a bytes MAC to a colon delimited string.
    """
    return ':'.join('{:02x}'.format(b) for b in bytes)

def bytes_to_ip(bytes):

    return socket.inet_ntoa(bytes)

def bytes_to_ipv6(bytes):

    return socket.inet_ntop(socket.AF_INET6, bytes)

def debug_to_log(payload):
    f_open = open('debug.log', 'ab')
    f_open.write(payload)
    f_open.close()

def get_manufacturer(self):
    if self.src_mac:
        self.oui = self.src_mac.replace(':', '')[:6]
        if self.oui in oui_table:
            self.manufacturer = oui_table[self.oui]
        else:
            self.manufacturer = 'Unknown'

class Client:
    def __init__(self, src_mac, client_ct):
            self.client_count = client_ct
            self.src_mac = src_mac
            self.ip_address = None
            self.ipv6_address = None
            self.oui = None
            self.manufacturer = None
            self.hostnames = set()
            self.vendor_class = None
            self.services = set()
            self.user_agents = set()
            self.oses = set()
            self.ttl = None
            self.ports = set()
            self.communicants = {}
            self.count = 0
            get_manufacturer(self)

    def to_dict(self):
        return {
            '#': self.client_count,
            'SOURCE': self.src_mac,
            'IPv4': self.ip_address,
            'IPv6': self.ipv6_address,
            'MANUFACTURER': self.manufacturer,
            'HOSTNAME': self.hostnames,
            'SERVICES': self.services,
            'TTL': self.ttl,
            'OS': self.oses,
            'PORTS': self.ports,
            'COUNTS': self.count
            #'COMMUNICANTS': ', '.join(f'{k}: {v}' for k, v in self.communicants.items()),
        }