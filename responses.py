#!/usr/bin/env python3

"""
Module to handle responses for ethodump-ng.
"""
import struct
import socket
import random

from globals import UUID_K, PK, PUBLIC_KEY_RSA_B64, mac_address_to_bytes, ResponseObject, generate_sha1_hash
from globals import PK, SHORT_PK, CID, VERSION_TRIPLET, LONG_VERSION, HOSTNAME, MODEL_NAME
from tcp_udp import ip_checksum, udp_checksum, create_udp_header, udp_ipv6_checksum
from igmp import calculate_igmp_checksum

MULTICAST_IP = '224.0.0.251'
MULTICAST_MAC = '01:00:5e:00:00:fb'
IPV6_MULTICAST_IP = 'ff02::fb'
IPV6_MULTICAST_MAC = '33:33:00:00:00:fb'
UDP_HEADER_LEN = 8
IP_HEADER_LEN = 20

MDNS_PTR = 12
MDNS_TXT = 16
MDNS_SRV = 33
MDNS_A = 1
MDNS_AAAA = 28
MDNS_NSEC = 47

spotify_get_response = {
        "status": 101,
        "statusString": "OK",
        "spotifyError": 0,
        "version": VERSION_TRIPLET,
        "deviceID": PK,
        "remoteName": HOSTNAME,
        "publicKey": SHORT_PK,
        "deviceType": "TV",
        "libraryVersion": LONG_VERSION,
        "brandDisplayName": "sony_tv",
        "modelDisplayName": MODEL_NAME,
        "groupStatus": "NONE",
        "resolverVersion": "1",
        "tokenType": "default",
        "clientID": CID,
        "scope": "umbrella-tv",
        "productID": 1,
        "availability": "NOT-LOADED",
        "supported_drm_media_formats": [
            {"drm": 1, "formats": 70},
            {"drm": 2, "formats": 70}
        ],
        "supported_capabilities": 3
    }

final_spotify_post_response = {
        "status": 101,
        "statusString": "OK",
        "spotifyError": 0
    }

spotify_post_response_bad_key = {
        "status": 203,
        "statusString": "ERROR-INVALID-PUBLICKEY",
        "spotifyError": 0,
        "version": VERSION_TRIPLET,
        "deviceID": PK,
        "publicKey": PUBLIC_KEY_RSA_B64
    }

youtube_get_response = f"""
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" xmlns:sec="http://www.sec.co.kr/dlna" xmlns:dlna="urn:schemas-dlna-org:device-1-0">
<specVersion>
<major>1</major>
<minor>0</minor>
</specVersion>
<device>
<deviceType>urn:dial-multiscreen-org:device:dialreceiver:1</deviceType>
<friendlyName>{HOSTNAME}</friendlyName>
<manufacturer>Sony</manufacturer>
<manufacturerURL>http://www.sony.com/sec</manufacturerURL>
<modelDescription>Sony DTV RCR</modelDescription>
<modelName>{MODEL_NAME}</modelName>
<modelNumber>1.0</modelNumber>
<modelURL>http://www.sony.com/sec</modelURL>
<serialNumber>{LONG_VERSION}</serialNumber>
<UDN>uuid:{UUID_K}</UDN>
<sec:deviceID>{PK}</sec:deviceID>
<sec:ProductCap>Resolution:1920X1080,Crystal,Y2023</sec:ProductCap>
<serviceList>
<service>
<serviceType>urn:dial-multiscreen-org:service:dial:1</serviceType>
<serviceId>urn:dial-multiscreen-org:serviceId:dial</serviceId>
<controlURL>/RCR/control/dial</controlURL>
<eventSubURL>/RCR/event/dial</eventSubURL>
<SCPDURL>dial.xml</SCPDURL>
</service>
</serviceList>
<sec:Capabilities>
<sec:Capability name="sony:multiscreen:1" port="7678" location="/ms/1.0/"/>
</sec:Capabilities>
</device>
</root>
"""

def create_igmp_membership_report(own_iface, skt: socket.socket):

    src_mac = mac_address_to_bytes(own_iface.mac)
    src_ip = socket.inet_aton(own_iface.ip)
    multicast_ip = socket.inet_aton(MULTICAST_IP)
    dst_mac = mac_address_to_bytes(MULTICAST_MAC)

    igmp_type = 0x16
    igmp_max_resp_time = 0
    igmp_checksum = 0
    
    igmp_payload = struct.pack('!BBH4s', igmp_type, igmp_max_resp_time, igmp_checksum, multicast_ip)
    igmp_len = len(igmp_payload)
    # Calculate igmp checksum
    igmp_payload = calculate_igmp_checksum(igmp_payload)

    eth_header = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)

    # ip header
    ver_header_len = 70 # version 4 + header length 24 (6)
    dsf = 192 # DSF
    identification = 0
    ip_header_len = 24
    ttl = 1
    ip_proto_igmp = 2
    flags_fragment_offset = 0x4000
    checksum = 0

    # ip header packing
    header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + igmp_len, identification, flags_fragment_offset, ttl, ip_proto_igmp, checksum, src_ip, multicast_ip)

    # add router alert option to ip header
    header_without_checksum += b'\x94\x04\x00\x00'

    calculated_checksum = ip_checksum(header_without_checksum)

    ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + igmp_len, identification, flags_fragment_offset, ttl, ip_proto_igmp, calculated_checksum, src_ip, multicast_ip)

    # re-add the router alert option
    ip_header += b'\x94\x04\x00\x00'

    pkt = eth_header + ip_header + igmp_payload

    skt.send(pkt)

def encode_mdns_name(name):
    """Encode a domain name according to mDNS requirements."""
    parts = name.split('.')
    encoded_parts = [len(part).to_bytes(1, 'big') + part.encode() for part in parts]
    return b''.join(encoded_parts) + b'\x00'

def encode_mdns_name_new(name, packet):
    labels = name.split('.')
    encoded_name = b''
    remaining_labels = labels.copy()

    while remaining_labels:
        for i in range(len(remaining_labels)):
            name_part = remaining_labels[i:]
            # Encode the name part to search in the packet
            search_part = b''.join(struct.pack('!B', len(label)) + label.encode() for label in name_part) #+ b'\x00'
            
            offset = packet.find(search_part)
            if offset != -1:
                # Add the unmatched labels followed by the pointer
                for label in labels[:i]:
                    encoded_name += struct.pack('!B', len(label)) + label.encode()
                pointer = 0xC000 | offset
                encoded_name += struct.pack('!H', pointer)
                return encoded_name
        
        # If no match is found, encode the current label
        encoded_name += struct.pack('!B', len(remaining_labels[0])) + remaining_labels[0].encode('utf-8')
        remaining_labels.pop(0)
    
    # Add the null-terminating byte at the end if no pointer was used
    encoded_name += b'\x00'
    return encoded_name

def send_spotify_response(resp: ResponseObject):
    service_name = resp.service
    src_mac = resp.src_mac
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    srv_port = resp.srv_port
    hostname = resp.hostname
    ip_version = resp.type_

    SHA1_HASH = generate_sha1_hash(src_mac)

    # mdns payload
    transaction_id = b'\x00\x00'
    flags = b'\x84\x00'
    questions = b'\x00\x00'
    answer_rrs = b'\x00\x01'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x05'

    full_spotify_name_field = encode_mdns_name(SHA1_HASH + '.' + service_name)

    ################ SPOTIFY PTR RECORD ##################
    name_field = encode_mdns_name(service_name)

    type_ = struct.pack('!H', MDNS_PTR)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)
    
    domain_name_text = SHA1_HASH + '.' + service_name
    encoded_domain_name = encode_mdns_name(domain_name_text)
    data_len = len(encoded_domain_name) + 2
    domain_name = encoded_domain_name + b'\xc0\x0c'

    spotify_ptr_record = name_field + type_ + class_ + time_to_live + int(data_len).to_bytes(2, 'big') + domain_name

    #################### MDNS A RECORD ####################
    domain_name = encode_mdns_name(hostname + '.' + 'local')
    type_ = struct.pack('!H', MDNS_A)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    ip_bytes = socket.inet_aton(src_ip)
    a_data_len = struct.pack('!H', len(ip_bytes))

    a_record = domain_name + type_ + class_ + time_to_live + a_data_len + ip_bytes

    ################## MDNS TXT RECORD ###################
    type_ = struct.pack('!H', MDNS_TXT)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    txt_cpath = "CPath=/zc".encode()
    txt_cpath_len = struct.pack('!B',len(txt_cpath))

    txt_payload = txt_cpath_len + txt_cpath
    txt_payload_len = struct.pack('!H', len(txt_payload))
    txt_record_spotify = full_spotify_name_field + type_ + class_ + time_to_live + txt_payload_len + txt_payload

    ################## MDNS SRV RECORD ###################
    type_ = struct.pack('!H', MDNS_SRV)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    priority = struct.pack('!H', 0)
    weight = struct.pack('!H', 0)
    port = struct.pack('!H', srv_port)
    target = encode_mdns_name(hostname + '.' + 'local')
    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))

    srv_record_spotify = full_spotify_name_field + type_ + class_ + time_to_live + srv_data_len + srv_data

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    nsec_bitmap = b'\x00\x04\x40\x00\x00\x00'
    nsec_data_len = struct.pack('!H',len(domain_name) + len(nsec_bitmap))

    nsec_a_record = domain_name + type_ + class_ + time_to_live + nsec_data_len + domain_name + nsec_bitmap

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
    nsec_data_len = struct.pack('!H',len(full_spotify_name_field) + len(nsec_bitmap))

    nsec_srv_txt_spotify_record = full_spotify_name_field + type_ + class_ + time_to_live + nsec_data_len + full_spotify_name_field + nsec_bitmap

    ################ BUILD MDNS PAYLOAD ##################
    mdns_payload = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + spotify_ptr_record + a_record + txt_record_spotify + srv_record_spotify + nsec_a_record + nsec_srv_txt_spotify_record
    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x0800
        dst_mac = MULTICAST_MAC
        multicast_mac = mac_address_to_bytes(dst_mac)
        eth_header = struct.pack("!6s6sH", multicast_mac, src_mac, eth_type)

        # ip header
        multicast_ip = MULTICAST_IP
        ver_header_len = 69 # version 4 + header length 20 (5)
        dsf = 0 # DSF
        identification = random.randint(0, 0xFFFF)
        ip_header_len = IP_HEADER_LEN
        udp_header_len = UDP_HEADER_LEN
        ttl = 255
        ip_proto_udp = 17
        flags_fragment_offset = 0
        checksum = 0

        # udp header
        header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

        calculated_checksum = ip_checksum(header_without_checksum)

        ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, calculated_checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_checksum(src_ip, multicast_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)
        
    elif ip_version == 6 and src_ipv6:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x86dd
        dst_mac = IPV6_MULTICAST_MAC
        multicast_mac = mac_address_to_bytes(dst_mac)
        eth_header = struct.pack("!6s6sH", multicast_mac, src_mac, eth_type)

        # ip header
        multicast_ip = IPV6_MULTICAST_IP
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, multicast_ip)
        version = 6 << 28
        traffic_class = 0 << 20
        flow_label = 0xd0200
        payload_len = UDP_HEADER_LEN + mdns_len
        next_header = socket.IPPROTO_UDP
        hop_limit = 255

        ip_header = struct.pack("!4sHBB16s16s", struct.pack("!I", version | (traffic_class << 20) | flow_label), payload_len, next_header, hop_limit, src_ip_bytes, dst_ip_bytes)

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_ipv6_checksum(src_ipv6, multicast_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)
    
    else:
        return None

    pkt = eth_header + ip_header + udp_header_with_checksum + mdns_payload
    
    return pkt

def send_airplay_response_new(resp: ResponseObject):
    hostname = resp.hostname
    service_name = resp.service
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    src_mac = resp.src_mac
    srv_port = resp.srv_port
    ip_version = resp.type_
    is_unicast = resp.unicast

    top_level_name = hostname
    domain_name = hostname + '.local'
    full_name = top_level_name + '.' + service_name + '.local'
    name_field = service_name

    mdns_payload = b''
    # mdns payload
    mdns_payload += b'\x00\x00'     # transaction id
    mdns_payload += b'\x84\x00'              # flags
    mdns_payload += b'\x00\x00'          # questions
    mdns_payload += b'\x00\x01'         # answer_rrs
    mdns_payload += b'\x00\x00'      # authority_rrs
    if is_unicast == 0:              
        mdns_payload += b'\x00\x06'  # additional rrs
    elif is_unicast == 1:
        mdns_payload += b'\x00\x04'

    ######################### PTR RECORD ############################
    mdns_payload += encode_mdns_name_new(name_field, mdns_payload)  # service name field
    mdns_payload += struct.pack('!H', MDNS_PTR)                     # type 
    mdns_payload += b'\x00\x01'                                     # class
    mdns_payload += struct.pack('!I', 4500)                         # ttl

    temp_payload = mdns_payload + b'\x00\x00'
    encoded_full_name = encode_mdns_name_new(full_name, temp_payload)
    data_len = len(encoded_full_name)
    mdns_payload += int(data_len).to_bytes(2, 'big')                # rdata_len field
    mdns_payload += encoded_full_name                               # domain name
    
    ######################## MDNS TXT RECORD ########################
    mdns_payload += encode_mdns_name_new(full_name, mdns_payload)   # hostname + service name
    mdns_payload += struct.pack('!H', MDNS_TXT)                     # type
    mdns_payload += b'\x80\x01'                                     # class
    mdns_payload += struct.pack('!I', 4500)                         # ttl

    device_id = src_mac.upper()
    psi_mac = src_mac.replace(':','').upper()    

    txt_acl = "acl=0".encode()
    txt_acl_len = struct.pack('!B',len(txt_acl))
    txt_deviceid = f"deviceid={device_id}".encode()
    txt_deviceid_len = struct.pack('!B',len(txt_deviceid))
    txt_features = "features=0x7F8AD0,0x38BCF46".encode()
    txt_features_len = struct.pack('!B',len(txt_features))
    txt_fex = "fex=0Ip/AEbPiwNACA".encode()
    txt_fex_len = struct.pack('!B',len(txt_fex))
    txt_rsf = "rsf=0x3".encode()
    txt_rsf_len = struct.pack('!B',len(txt_rsf))
    txt_fv = "fv=p20.10.00.4102".encode()
    txt_fv_len = struct.pack('!B',len(txt_fv))
    txt_at = "at=0x1".encode()
    txt_at_len = struct.pack('!B',len(txt_at))
    txt_flags = "flags=0x244".encode()
    txt_flags_len = struct.pack('!B',len(txt_flags))
    txt_model = "model=appletv6,2".encode()
    txt_model_len = struct.pack('!B',len(txt_model))
    txt_integrator = "integrator=sony_tv".encode()
    txt_integrator_len = struct.pack('!B',len(txt_integrator))
    txt_manufacturer = "manufacturer=Sony".encode()
    txt_manufacturer_len = struct.pack('!B',len(txt_manufacturer))
    txt_serial_number = f"serialNumber={UUID_K}".encode()
    txt_serial_number_len = struct.pack('!B',len(txt_serial_number))
    txt_protovers = "protovers=1.1".encode()
    txt_protovers_len = struct.pack('!B',len(txt_protovers))
    txt_srcvers = "srcvers=377.40.00".encode()
    txt_srcvers_len = struct.pack('!B',len(txt_srcvers))
    txt_pi = f"pi={device_id}".encode()
    txt_pi_len = struct.pack('!B',len(txt_pi))
    txt_psi = f"psi=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_psi_len = struct.pack('!B',len(txt_psi))
    txt_gid = f"gid=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_gid_len = struct.pack('!B',len(txt_gid))
    txt_gcgl = "gcgl=0".encode()
    txt_gcgl_len = struct.pack('!B',len(txt_gcgl))
    txt_pk = f"pk={PK}".encode()
    txt_pk_len = struct.pack('!B',len(txt_pk))

    txt_payload = txt_acl_len + txt_acl + txt_deviceid_len + txt_deviceid + txt_features_len + txt_features + txt_fex_len + txt_fex +\
        txt_rsf_len + txt_rsf + txt_fv_len + txt_fv + txt_at_len + txt_at + txt_flags_len + txt_flags + txt_model_len + txt_model +\
        txt_integrator_len + txt_integrator + txt_manufacturer_len + txt_manufacturer + txt_serial_number_len + txt_serial_number +\
        txt_protovers_len + txt_protovers + txt_srcvers_len + txt_srcvers + txt_pi_len + txt_pi + txt_psi_len + txt_psi + txt_gid_len +\
        txt_gid + txt_gcgl_len + txt_gcgl + txt_pk_len + txt_pk

    txt_payload_len = struct.pack('!H', len(txt_payload))
    
    mdns_payload += txt_payload_len                               # TXT payload len
    mdns_payload += txt_payload                                   # TXT payload

    ################## MDNS SRV RECORD ############################
    mdns_payload += encode_mdns_name_new(full_name, mdns_payload) # hostname + service name
    mdns_payload += struct.pack('!H', MDNS_SRV)                   # SRV Type
    mdns_payload += b'\x80\x01'                                   # Class (CF/IN)
    mdns_payload += struct.pack('!I', 120)                        # ttl

    priority = struct.pack('!H', 0)                               # priority
    weight = struct.pack('!H', 0)                                 # weight
    port = struct.pack('!H', srv_port)                            # port
    
    temp_payload = mdns_payload + b'\x00\x00' + priority + weight + port
    target = encode_mdns_name_new(domain_name, temp_payload)      # target

    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))               # RDATA length

    mdns_payload = mdns_payload + srv_data_len + srv_data

    ####################### MDNS A RECORD #########################
    mdns_payload += encode_mdns_name_new(domain_name, mdns_payload)    # A name
    mdns_payload += struct.pack('!H', MDNS_A)                     # Type
    mdns_payload += b'\x80\x01'                                   # Class (CF/IN)
    mdns_payload += struct.pack('!I', 120)                        # ttl

    ip_bytes = socket.inet_aton(src_ip)
    a_data_len = struct.pack('!H', len(ip_bytes))

    mdns_payload += a_data_len                                    # RDATA len
    mdns_payload += ip_bytes                                      # IPv4

    ##################### MDNS AAAA RECORD ##########################
    mdns_payload += encode_mdns_name_new(domain_name, mdns_payload) # AAAA Name
    mdns_payload += struct.pack('!H', MDNS_AAAA)                    # Type
    mdns_payload += b'\x80\x01'                                     # Class
    mdns_payload += struct.pack('!I', 120)                          # ttl

    ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
    aaaa_data_len = struct.pack('!H', len(ip_bytes))

    mdns_payload += aaaa_data_len                                   # RDATA len
    mdns_payload += ip_bytes                                        # IPv6

    if is_unicast == 0:
        ###################### MDNS NSEC RECORD #########################
        nsec_name = encode_mdns_name_new(domain_name, mdns_payload)  
        mdns_payload += nsec_name                                       # NSEC Name
        mdns_payload += struct.pack('!H', MDNS_NSEC)                    # Type
        mdns_payload += b'\x80\x01'                                     # Class (CF/IN)
        mdns_payload += struct.pack('!I', 120)                          # ttl

        #nsec_bitmap = b'\x00\x04\x40\x00\x00\x00'# without AAAA
        nsec_bitmap = b'\x00\x04\x40\x00\x00\x08'
        nsec_data_len = struct.pack('!H',len(nsec_name) + len(nsec_bitmap))

        mdns_payload += nsec_data_len                                   # RDATA len
        mdns_payload += encode_mdns_name_new(domain_name, mdns_payload) # NSEC Name
        mdns_payload += nsec_bitmap                                     # NSEC bitmap

        ###################### MDNS NSEC RECORD #########################
        nsec_name = encode_mdns_name_new(full_name, mdns_payload)
        mdns_payload += nsec_name                                       # NSEC Name
        mdns_payload += struct.pack('!H', MDNS_NSEC)                    # Type
        mdns_payload += b'\x80\x01'                                     # Class (CF/IN)
        mdns_payload += struct.pack('!I', 4500)                         # ttl

        nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
        nsec_data_len = struct.pack('!H',len(nsec_name) + len(nsec_bitmap))

        mdns_payload += nsec_data_len                                   # RDATA len
        mdns_payload += encode_mdns_name_new(full_name, mdns_payload)   # NSEC Name
        mdns_payload += nsec_bitmap

    ################ BUILD MDNS PAYLOAD ##################
    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x0800
        if is_unicast == 0:
            dst_mac = mac_address_to_bytes(MULTICAST_MAC)
        elif is_unicast == 1:
            dst_mac = mac_address_to_bytes(resp.dst_mac)
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, eth_type)

        # ip header
        if is_unicast == 0:
            dst_ip = MULTICAST_IP
        elif is_unicast == 1:
            dst_ip = resp.dst_ip

        ver_header_len = 69 # version 4 + header length 20 (5)
        dsf = 0 # DSF
        identification = random.randint(0, 0xFFFF)
        ip_header_len = IP_HEADER_LEN
        udp_header_len = UDP_HEADER_LEN
        ttl = 255
        ip_proto_udp = 17
        flags_fragment_offset = 0x4000
        checksum = 0

        # udp header
        header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

        calculated_checksum = ip_checksum(header_without_checksum)

        ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, calculated_checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_checksum(src_ip, dst_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

    elif ip_version == 6 and src_ipv6:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x86dd
        if is_unicast == 0:
            dst_mac = mac_address_to_bytes(IPV6_MULTICAST_MAC)
        elif is_unicast == 1:
            dst_mac = mac_address_to_bytes(resp.dst_mac)
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, eth_type)

        # ip header
        if is_unicast == 0:
            dst_ip = IPV6_MULTICAST_IP
        elif is_unicast == 1:
            dst_ip = resp.dst_ip

        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
        version = 6 << 28
        traffic_class = 0 << 20
        flow_label = 0xd0200
        payload_len = UDP_HEADER_LEN + mdns_len
        next_header = socket.IPPROTO_UDP
        hop_limit = 255

        ip_header = struct.pack("!4sHBB16s16s", struct.pack("!I", version | (traffic_class << 20) | flow_label), payload_len, next_header, hop_limit, src_ip_bytes, dst_ip_bytes)

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_ipv6_checksum(src_ipv6, dst_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

    else:
        return None

    pkt = eth_header + ip_header + udp_header_with_checksum + mdns_payload

    return pkt

def send_airplay_response(resp: ResponseObject):
    hostname = resp.hostname
    service_name = resp.service
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    src_mac = resp.src_mac
    srv_port = resp.srv_port
    ip_version = resp.type_
    is_unicast = resp.unicast

    top_level_name = hostname
    domain_name = encode_mdns_name(hostname + '.local')
    full_name = encode_mdns_name(top_level_name + '.' + service_name)
    name_field = encode_mdns_name(service_name)

    # mdns payload
    transaction_id = b'\x00\x00'
    flags = b'\x84\x00'
    questions = b'\x00\x00'
    answer_rrs = b'\x00\x01'
    authority_rrs = b'\x00\x00'
    if is_unicast == 0:
        additional_rrs = b'\x00\x06'
    elif is_unicast == 1:
        additional_rrs = b'\x00\x04'

    ################ PTR RECORD ##################
    type_ = struct.pack('!H', MDNS_PTR)
    class_ = b'\x00\x01'
    time_to_live = struct.pack('!I', 4500)

    data_len = len(full_name) + 2
    domain_name = full_name + b'\xc0\x0c'

    ptr_record = name_field + type_ + class_ + time_to_live + int(data_len).to_bytes(2, 'big') + domain_name
    
    ################## MDNS TXT RECORD ###################
    type_ = struct.pack('!H', MDNS_TXT)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    device_id = src_mac.upper()
    psi_mac = src_mac.replace(':','').upper()    

    txt_acl = "acl=0".encode()
    txt_acl_len = struct.pack('!B',len(txt_acl))
    txt_deviceid = f"deviceid={device_id}".encode()
    txt_deviceid_len = struct.pack('!B',len(txt_deviceid))
    txt_features = "features=0x7F8AD0,0x38BCF46".encode()
    txt_features_len = struct.pack('!B',len(txt_features))
    txt_fex = "fex=0Ip/AEbPiwNACA".encode()
    txt_fex_len = struct.pack('!B',len(txt_fex))
    txt_rsf = "rsf=0x3".encode()
    txt_rsf_len = struct.pack('!B',len(txt_rsf))
    txt_fv = "fv=p20.10.00.4102".encode()
    txt_fv_len = struct.pack('!B',len(txt_fv))
    txt_at = "at=0x1".encode()
    txt_at_len = struct.pack('!B',len(txt_at))
    txt_flags = "flags=0x244".encode()
    txt_flags_len = struct.pack('!B',len(txt_flags))
    txt_model = "model=appletv6,2".encode()
    txt_model_len = struct.pack('!B',len(txt_model))
    txt_integrator = "integrator=sony_tv".encode()
    txt_integrator_len = struct.pack('!B',len(txt_integrator))
    txt_manufacturer = "manufacturer=Sony".encode()
    txt_manufacturer_len = struct.pack('!B',len(txt_manufacturer))
    txt_serial_number = f"serialNumber={UUID_K}".encode()
    txt_serial_number_len = struct.pack('!B',len(txt_serial_number))
    txt_protovers = "protovers=1.1".encode()
    txt_protovers_len = struct.pack('!B',len(txt_protovers))
    txt_srcvers = "srcvers=377.40.00".encode()
    txt_srcvers_len = struct.pack('!B',len(txt_srcvers))
    txt_pi = f"pi={device_id}".encode()
    txt_pi_len = struct.pack('!B',len(txt_pi))
    txt_psi = f"psi=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_psi_len = struct.pack('!B',len(txt_psi))
    txt_gid = f"gid=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_gid_len = struct.pack('!B',len(txt_gid))
    txt_gcgl = "gcgl=0".encode()
    txt_gcgl_len = struct.pack('!B',len(txt_gcgl))
    txt_pk = f"pk={PK}".encode()
    txt_pk_len = struct.pack('!B',len(txt_pk))

    txt_payload = txt_acl_len + txt_acl + txt_deviceid_len + txt_deviceid + txt_features_len + txt_features + txt_fex_len + txt_fex +\
        txt_rsf_len + txt_rsf + txt_fv_len + txt_fv + txt_at_len + txt_at + txt_flags_len + txt_flags + txt_model_len + txt_model +\
        txt_integrator_len + txt_integrator + txt_manufacturer_len + txt_manufacturer + txt_serial_number_len + txt_serial_number +\
        txt_protovers_len + txt_protovers + txt_srcvers_len + txt_srcvers + txt_pi_len + txt_pi + txt_psi_len + txt_psi + txt_gid_len +\
        txt_gid + txt_gcgl_len + txt_gcgl + txt_pk_len + txt_pk

    txt_payload_len = struct.pack('!H', len(txt_payload))
    txt_record = full_name + type_ + class_ + time_to_live + txt_payload_len + txt_payload

    #################### MDNS A RECORD ####################
    a_name = encode_mdns_name(hostname + '.' + 'local')
    type_ = struct.pack('!H', MDNS_A)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    ip_bytes = socket.inet_aton(src_ip)
    a_data_len = struct.pack('!H', len(ip_bytes))

    a_record = a_name + type_ + class_ + time_to_live + a_data_len + ip_bytes

    ################# MDNS AAAA RECORD ####################
    aaaa_name = encode_mdns_name(hostname + '.' + 'local')
    type_ = struct.pack('!H', MDNS_AAAA)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
    aaaa_data_len = struct.pack('!H', len(ip_bytes))

    aaaa_record = aaaa_name + type_ + class_ + time_to_live + aaaa_data_len + ip_bytes

    ################## MDNS SRV RECORD ###################
    type_ = struct.pack('!H', MDNS_SRV)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    priority = struct.pack('!H', 0)
    weight = struct.pack('!H', 0)
    port = struct.pack('!H', srv_port)
    target = encode_mdns_name(hostname + '.local')
    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))

    srv_record = full_name + type_ + class_ + time_to_live + srv_data_len + srv_data

    ################ MDNS NSEC RECORD ####################
    nsec_name = encode_mdns_name(hostname + '.' + 'local')
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    #nsec_bitmap = b'\x00\x04\x40\x00\x00\x00'# without AAAA
    nsec_bitmap = b'\x00\x04\x40\x00\x00\x08'
    nsec_data_len = struct.pack('!H',len(nsec_name) + len(nsec_bitmap))

    nsec_a_record = nsec_name + type_ + class_ + time_to_live + nsec_data_len + nsec_name + nsec_bitmap

     ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
    nsec_data_len = struct.pack('!H',len(full_name) + len(nsec_bitmap))

    nsec_srv_txt_record = full_name + type_ + class_ + time_to_live + nsec_data_len + full_name + nsec_bitmap

    ################ BUILD MDNS PAYLOAD ##################
    if is_unicast == 0:
        mdns_payload = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + ptr_record + a_record + aaaa_record + txt_record + srv_record + nsec_a_record + nsec_srv_txt_record
    elif is_unicast == 1:
        mdns_payload = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + ptr_record + txt_record + srv_record + a_record + aaaa_record
    
    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x0800
        if is_unicast == 0:
            dst_mac = mac_address_to_bytes(MULTICAST_MAC)
        elif is_unicast == 1:
            dst_mac = mac_address_to_bytes(resp.dst_mac)
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, eth_type)

        # ip header
        if is_unicast == 0:
            dst_ip = MULTICAST_IP
        elif is_unicast == 1:
            dst_ip = resp.dst_ip

        ver_header_len = 69 # version 4 + header length 20 (5)
        dsf = 0 # DSF
        identification = random.randint(0, 0xFFFF)
        ip_header_len = IP_HEADER_LEN
        udp_header_len = UDP_HEADER_LEN
        ttl = 255
        ip_proto_udp = 17
        flags_fragment_offset = 0x4000
        checksum = 0

        # udp header
        header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

        calculated_checksum = ip_checksum(header_without_checksum)

        ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, calculated_checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_checksum(src_ip, dst_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

    elif ip_version == 6 and src_ipv6:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x86dd
        if is_unicast == 0:
            dst_mac = mac_address_to_bytes(IPV6_MULTICAST_MAC)
        elif is_unicast == 1:
            dst_mac = mac_address_to_bytes(resp.dst_mac)
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, eth_type)

        # ip header
        if is_unicast == 0:
            dst_ip = IPV6_MULTICAST_IP
        elif is_unicast == 1:
            dst_ip = resp.dst_ip

        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
        version = 6 << 28
        traffic_class = 0 << 20
        flow_label = 0xd0200
        payload_len = UDP_HEADER_LEN + mdns_len
        next_header = socket.IPPROTO_UDP
        hop_limit = 255

        ip_header = struct.pack("!4sHBB16s16s", struct.pack("!I", version | (traffic_class << 20) | flow_label), payload_len, next_header, hop_limit, src_ip_bytes, dst_ip_bytes)

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_ipv6_checksum(src_ipv6, dst_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

    else:
        return None

    pkt = eth_header + ip_header + udp_header_with_checksum + mdns_payload

    return pkt

def send_query(resp: ResponseObject):
    service_name = resp.service
    src_ip = resp.src_ip
    src_mac = resp.src_mac
    ip_version = resp.type_

    name_field = encode_mdns_name(service_name)

    # mdns payload
    transaction_id = b'\x00\x00'
    flags = b'\x84\x00'
    questions = b'\x00\x01'
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'

    ################ PTR RECORD ##################
    type_ = struct.pack('!H', MDNS_PTR)
    class_ = b'\x00\x01'

    ptr_record = name_field + type_ + class_

    mdns_payload = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + ptr_record
    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        src_mac = mac_address_to_bytes(src_mac)
        eth_type = 0x0800
        dst_mac = MULTICAST_MAC
        multicast_mac = mac_address_to_bytes(dst_mac)
        eth_header = struct.pack("!6s6sH", multicast_mac, src_mac, eth_type)

        # ip header
        multicast_ip = MULTICAST_IP
        ver_header_len = 69 # version 4 + header length 20 (5)
        dsf = 0 # DSF
        identification = random.randint(0, 0xFFFF)
        ip_header_len = IP_HEADER_LEN
        udp_header_len = UDP_HEADER_LEN
        ttl = 255
        ip_proto_udp = 17
        flags_fragment_offset = 0
        checksum = 0

        # udp header
        header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

        calculated_checksum = ip_checksum(header_without_checksum)

        ip_header = struct.pack("!BBHHHBBH4s4s", ver_header_len, dsf, ip_header_len + udp_header_len + mdns_len, identification, flags_fragment_offset, ttl, ip_proto_udp, calculated_checksum, socket.inet_aton(src_ip), socket.inet_aton(multicast_ip))

        udp_header = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, 0)
        checksum = udp_checksum(src_ip, multicast_ip, UDP_HEADER_LEN + mdns_len, udp_header, mdns_payload)
        udp_header_with_checksum = create_udp_header(5353, 5353, UDP_HEADER_LEN + mdns_len, checksum)

        pkt = eth_header + ip_header + udp_header_with_checksum + mdns_payload

    else:
        return None

    return pkt

"""

    if 'google' in service_name:
        txt_id = f"id={psi_mac.upper()}".encode()
        txt_id_len = struct.pack('!B',len(txt_id))
        txt_cd = f"cd={UUID_K}".encode()
        txt_cd_len = struct.pack('!B',len(txt_cd))
        txt_ve = f"ve=05".encode()
        txt_ve_len = struct.pack('!B', len(txt_ve))
        txt_md = "md=Chromecast".encode()
        txt_md_len = struct.pack('!B', len(txt_md))
        txt_ic = "ic=/setup/icon.png".encode()
        txt_ic_len = struct.pack('!B', len(txt_ic))
        txt_fn = hostname.encode()
        txt_fn_len = struct.pack('!B', len(txt_fn))
        txt_ca = "ca=4101".encode()
        txt_ca_len = struct.pack('!B', len(txt_ca))
        txt_st = "st=0".encode()
        txt_st_len = struct.pack('!B', len(txt_st))
        txt_nf = "nf=1".encode()
        txt_nf_len = struct.pack('!B', len(txt_nf))
        txt_rs = "rs=Ready to Cast".encode()
        txt_rs_len = struct.pack('!B', len(txt_rs))

        txt_payload = txt_id_len + txt_id + txt_cd_len + txt_cd + txt_ve_len + txt_ve + txt_md_len + txt_md + txt_ic_len + txt_ic +\
            txt_fn_len + txt_fn + txt_ca_len + txt_ca + txt_st_len + txt_st + txt_nf_len + txt_nf + txt_rs_len + txt_rs

    ################## MDNS TXT RECORD ###################
    type_ = struct.pack('!H', MDNS_TXT)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    device_id = src_mac.upper()
    psi_mac = src_mac.replace(':','').upper()
    txt_acl = "acl=0".encode()
    txt_acl_len = struct.pack('!B',len(txt_acl))
    txt_deviceid = f"deviceid={device_id}".encode()
    txt_deviceid_len = struct.pack('!B',len(txt_deviceid))
    txt_features = "features=0x7F8AD0,0x38BCF46".encode()
    txt_features_len = struct.pack('!B',len(txt_features))
    txt_fex = "fex=0Ip/AEbPiwNACA".encode()
    txt_fex_len = struct.pack('!B',len(txt_fex))
    txt_rsf = "rsf=0x3".encode()
    txt_rsf_len = struct.pack('!B',len(txt_rsf))
    txt_fv = "fv=p20.10.00.4102".encode()
    txt_fv_len = struct.pack('!B',len(txt_fv))
    txt_at = "at=0x1".encode()
    txt_at_len = struct.pack('!B',len(txt_at))
    txt_flags = "flags=0x244".encode()
    txt_flags_len = struct.pack('!B',len(txt_flags))
    txt_model = "model=appletv6,2".encode()
    txt_model_len = struct.pack('!B',len(txt_model))
    txt_integrator = "integrator=sony_tv".encode()
    txt_integrator_len = struct.pack('!B',len(txt_integrator))
    txt_manufacturer = "manufacturer=Sony".encode()
    txt_manufacturer_len = struct.pack('!B',len(txt_manufacturer))
    txt_serial_number = f"serialNumber={UUID_K}".encode()
    txt_serial_number_len = struct.pack('!B',len(txt_serial_number))
    txt_protovers = "protovers=1.1".encode()
    txt_protovers_len = struct.pack('!B',len(txt_protovers))
    txt_srcvers = "srcvers=377.40.00".encode()
    txt_srcvers_len = struct.pack('!B',len(txt_srcvers))
    txt_pi = f"pi={device_id}".encode()
    txt_pi_len = struct.pack('!B',len(txt_pi))
    txt_psi = f"psi=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_psi_len = struct.pack('!B',len(txt_psi))
    txt_gid = f"gid=00000000-0000-0000-0000-{psi_mac}".encode()
    txt_gid_len = struct.pack('!B',len(txt_gid))
    txt_gcgl = "gcgl=0".encode()
    txt_gcgl_len = struct.pack('!B',len(txt_gcgl))
    txt_pk = f"pk={PK}".encode()
    txt_pk_len = struct.pack('!B',len(txt_pk))

    txt_payload = txt_acl_len + txt_acl + txt_deviceid_len + txt_deviceid + txt_features_len + txt_features + txt_fex_len + txt_fex +\
        txt_rsf_len + txt_rsf + txt_fv_len + txt_fv + txt_at_len + txt_at + txt_flags_len + txt_flags + txt_model_len + txt_model +\
        txt_integrator_len + txt_integrator + txt_manufacturer_len + txt_manufacturer + txt_serial_number_len + txt_serial_number +\
        txt_protovers_len + txt_protovers + txt_srcvers_len + txt_srcvers + txt_pi_len + txt_pi + txt_psi_len + txt_psi + txt_gid_len +\
        txt_gid + txt_gcgl_len + txt_gcgl + txt_pk_len + txt_pk

    txt_payload_len = struct.pack('!H', len(txt_payload))
    txt_record = full_airplay_name_field + type_ + class_ + time_to_live + txt_payload_len + txt_payload

    ################## MDNS SRV RECORD ###################
    type_ = struct.pack('!H', MDNS_SRV)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 120)

    priority = struct.pack('!H', 0)
    weight = struct.pack('!H', 0)
    port = struct.pack('!H', srv_port)
    target = encode_mdns_name(hostname + '.' + 'local')
    srv_data = priority + weight + port + target
    srv_data_len = struct.pack('!H', len(srv_data))

    srv_record = full_airplay_name_field + type_ + class_ + time_to_live + srv_data_len + srv_data

    ################ MDNS NSEC RECORD ####################
    type_ = struct.pack('!H', MDNS_NSEC)
    class_ = b'\x80\x01'
    time_to_live = struct.pack('!I', 4500)

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'
    nsec_data_len = struct.pack('!H',len(full_airplay_name_field) + len(nsec_bitmap))

    nsec_srv_txt_airplay_record = full_airplay_name_field + type_ + class_ + time_to_live + nsec_data_len + full_airplay_name_field + nsec_bitmap
"""