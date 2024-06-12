#!/usr/bin/env python3

"""
Module to handle responses for ethodump-ng.
"""
import struct
import socket
import random

from globals import (UUID_K, PK, PUBLIC_KEY_RSA_B64, mac_address_to_bytes, 
    ResponseObject, generate_sha1_hash, PK, SHORT_PK, CID, VERSION_TRIPLET, 
    LONG_VERSION, HOSTNAME, MODEL_NAME, SHA1_HASH)
from tcp_udp import ip_checksum, udp_checksum, create_udp_header, udp_ipv6_checksum
from igmp import calculate_igmp_checksum

MULTICAST_IP = '224.0.0.251'
MULTICAST_MAC = '01:00:5e:00:00:fb'
IPV6_MULTICAST_IP = 'ff02::fb'
IPV6_MULTICAST_MAC = '33:33:00:00:00:fb'
UDP_HEADER_LEN = 8
IP_HEADER_LEN = 20

SPOTIFY = 'spotify'
AIRPLAY = 'airplay'
GOOGLECAST = 'google'

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


chromecase_test = """
<?xml version="1.0" encoding="utf-8"?>
<Client name="Chromecast">
  <!-- Author: Plex Inc. -->
  <!-- Updated for Chromecast Ultra by ambroisemaupate. -->
  <TranscodeTargets>
    <VideoProfile protocol="http" container="mkv" codec="h264" audioCodec="aac,mp3" context="streaming" />
    <MusicProfile container="mkv" codec="opus" />
    <PhotoProfile container="jpeg" />
    <SubtitleProfile container="ass" codec="ass" />
  </TranscodeTargets>
  <DirectPlayProfiles>
    <VideoProfile container="mkv" codec="mpeg1video,mpeg2video,mpeg4,h264,vp8,vp9,Hevc,h265" audioCodec="eac3,ac3,dca,aac,mp2,mp3,pcm" subtitleFormat="srt,ass" />
    <VideoProfile container="mp4,webm" codec="h264,mpeg4,Hevc,h265,vp8,vp9" audioCodec="eac3,ac3,dca,aac,mp2,mp3,pcm" subtitleFormat="srt,ass" />
    <MusicProfile container="mp3" codec="mp2,mp3" />
    <MusicProfile container="mp4" codec="eac3,ac3,dca,aac,mp2,mp3,pcm" />
    <MusicProfile container="flac" codec="flac" />
    <MusicProfile container="ogg" codec="vorbis" />
    <PhotoProfile container="jpeg,gif,webp,png" />
    <SubtitleProfile container="ass" codec="ass" />
    <SubtitleProfile container="srt" codec="srt" />
  </DirectPlayProfiles>
  <CodecProfiles>
    <VideoCodec name="h265,Hevc,vp9">
      <Limitations>
        <UpperBound name="video.width" value="3840"/>
        <UpperBound name="video.height" value="2176"/>
		    <UpperBound name="video.bitrate" value="75000"/>
      </Limitations>
    </VideoCodec>
    <VideoCodec name="h264,mpeg4">
      <Limitations>
        <UpperBound name="video.width" value="3840"/>
        <UpperBound name="video.height" value="2176"/>
        <UpperBound name="video.bitrate" value="75000"/>
		    <UpperBound name="video.bitDepth" value="10" />
        <UpperBound name="video.level" value="42" />
      </Limitations>
    </VideoCodec>
    <VideoAudioCodec name="mp3">
      <Limitations>
        <UpperBound name="audio.channels" value="2" />
      </Limitations>
    </VideoAudioCodec>
    <VideoAudioCodec name="aac">
      <Limitations>
        <UpperBound name="audio.channels" value="2" />
      </Limitations>
    </VideoAudioCodec>
    <VideoAudioCodec name="ac3">
      <Limitations>
        <UpperBound name="audio.channels" value="6" />
      </Limitations>
    </VideoAudioCodec>
    <VideoAudioCodec name="eac3">
      <Limitations>
        <UpperBound name="audio.channels" value="6" />
      </Limitations>
    </VideoAudioCodec>
    <VideoAudioCodec name="dca">
      <Limitations>
        <UpperBound name="audio.channels" value="6" />
      </Limitations>
    </VideoAudioCodec>
  </CodecProfiles>
</Client>
"""

chromecast_device_desc_xml = """"
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <URLBase>http://192.168.10.153:70000</URLBase>
  <device>
    <deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
    <friendlyName>Chromecast1234</friendlyName>
    <manufacturer>Google Inc.</manufacturer>
    <modelName>Eureka Dongle</modelName>
    <UDN>uuid:0b92d3ae-9f2a-d875-9e27-8934e2a7e178</UDN>
    <iconList>
      <icon>
        <mimetype>image/png</mimetype>
        <width>98</width>
        <height>55</height>
        <depth>32</depth>
        <url>/setup/icon.png</url>
      </icon>
    </iconList>
    <serviceList>
      <service>
        <serviceType>urn:dial-multiscreen-org:service:dial:1</serviceType>
        <serviceId>urn:dial-multiscreen-org:serviceId:dial</serviceId>
        <controlURL>/ssdp/notfound</controlURL>
        <eventSubURL>/ssdp/notfound</eventSubURL>
        <SCPDURL>http://www.google.com/cast</SCPDURL>
      </service>
    </serviceList>
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

def build_mdns_header(mdns_payload: bytes, flags: int, answer_rrs: int, additional_rrs: int, questions: int=0) -> bytes:

    mdns_payload += b'\x00\x00'                           # transaction id
    mdns_payload += struct.pack('!H', flags)              # flags
    mdns_payload += struct.pack('!H', questions)          # questions
    mdns_payload += struct.pack('!H', answer_rrs)         # answer_rrs
    mdns_payload += b'\x00\x00'                           # authority_rrs
    mdns_payload += struct.pack('!H', additional_rrs)     # additional rrs

    return mdns_payload

def build_ptr_record(mdns_payload: bytes, name_field: str, full_name: str) -> bytes:

    ######################### PTR RECORD ############################
    mdns_payload += encode_mdns_name_new(name_field, mdns_payload)  # service name field
    mdns_payload += struct.pack('!H', MDNS_PTR)                     # type 
    mdns_payload += b'\x00\x01'                                     # class
    mdns_payload += struct.pack('!I', 4500)                         # ttl

    if not full_name:
        return mdns_payload

    temp_payload = mdns_payload + b'\x00\x00'
    encoded_full_name = encode_mdns_name_new(full_name, temp_payload)
    data_len = len(encoded_full_name)
    mdns_payload += int(data_len).to_bytes(2, 'big')                # rdata_len field
    mdns_payload += encoded_full_name                               # domain name

    return mdns_payload

def build_a_record(mdns_payload: bytes, domain_name: str, src_ip: str) -> bytes:

    ####################### MDNS A RECORD ##########################
    mdns_payload += encode_mdns_name_new(domain_name, mdns_payload)# A name
    mdns_payload += struct.pack('!H', MDNS_A)                      # Type
    mdns_payload += b'\x80\x01'                                    # Class (CF/IN)
    mdns_payload += struct.pack('!I', 120)                         # ttl

    ip_bytes = socket.inet_aton(src_ip)
    a_data_len = struct.pack('!H', len(ip_bytes))

    mdns_payload += a_data_len                                     # RDATA len
    mdns_payload += ip_bytes                                       # IPv4

    return mdns_payload

def build_aaaa_record(mdns_payload: bytes, domain_name: str, src_ipv6: str) -> bytes:

    ##################### MDNS AAAA RECORD ##########################
    mdns_payload += encode_mdns_name_new(domain_name, mdns_payload) # AAAA Name
    mdns_payload += struct.pack('!H', MDNS_AAAA)                    # Type
    mdns_payload += b'\x80\x01'                                     # Class
    mdns_payload += struct.pack('!I', 120)                          # ttl

    ip_bytes = socket.inet_pton(socket.AF_INET6, src_ipv6)
    aaaa_data_len = struct.pack('!H', len(ip_bytes))

    mdns_payload += aaaa_data_len                                   # RDATA len
    mdns_payload += ip_bytes                                        # IPv6

    return mdns_payload

def build_cpath_zc_txt_payload() -> bytes:

    txt_cpath = "CPath=/zc".encode()
    txt_cpath_len = struct.pack('!B',len(txt_cpath))

    txt_payload = txt_cpath_len + txt_cpath
    txt_payload_len = struct.pack('!H', len(txt_payload))

    return txt_payload_len, txt_payload

def build_airplay_txt_payload(src_mac: str) -> bytes:

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

    return txt_payload_len, txt_payload

def build_googlecast_txt_payload(src_mac: str, hostname: str) -> bytes:

    psi_mac = src_mac.replace(':','').upper()

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

    txt_payload_len = struct.pack('!H', len(txt_payload))

    return txt_payload_len, txt_payload

def build_txt_record(mdns_payload: bytes, full_name: str, service: str, src_mac:str=None, hostname: str=None) -> bytes:

    ######################## MDNS TXT RECORD ########################
    mdns_payload += encode_mdns_name_new(full_name, mdns_payload)   # hostname + service name
    mdns_payload += struct.pack('!H', MDNS_TXT)                     # type
    mdns_payload += b'\x80\x01'                                     # class
    mdns_payload += struct.pack('!I', 4500)                         # ttl

    if service == SPOTIFY:
        txt_payload_len, txt_payload = build_cpath_zc_txt_payload()
    elif service == AIRPLAY:
        txt_payload_len, txt_payload = build_airplay_txt_payload(src_mac)
    elif service == GOOGLECAST:
        txt_payload_len, txt_payload = build_googlecast_txt_payload(src_mac, hostname)

    mdns_payload += txt_payload_len
    mdns_payload += txt_payload

    return mdns_payload

def build_srv_record(mdns_payload: bytes, full_name: str, domain_name: str, srv_port: int) -> bytes:

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

    return mdns_payload

def build_nsec_a_aaaa_record(mdns_payload: bytes, domain_name: str, just_a=1) -> bytes:

    ###################### MDNS NSEC RECORD #########################
    nsec_name = encode_mdns_name_new(domain_name, mdns_payload)  
    mdns_payload += nsec_name                                       # NSEC Name
    mdns_payload += struct.pack('!H', MDNS_NSEC)                    # Type
    mdns_payload += b'\x80\x01'                                     # Class (CF/IN)
    mdns_payload += struct.pack('!I', 120)                          # ttl

    if just_a == 1:
        nsec_bitmap = b'\x00\x04\x40\x00\x00\x00'                   # without AAAA
    else:
        nsec_bitmap = b'\x00\x04\x40\x00\x00\x08'                   # with AAAA

    nsec_data_len = struct.pack('!H',len(nsec_name) + len(nsec_bitmap))

    mdns_payload += nsec_data_len                                   # RDATA len
    mdns_payload += encode_mdns_name_new(domain_name, mdns_payload) # NSEC Name
    mdns_payload += nsec_bitmap                                     # NSEC bitmap

    return mdns_payload

def build_nsec_srv_txt_record(mdns_payload: bytes, full_name: str) -> bytes:

    ###################### MDNS NSEC RECORD #########################
    nsec_name = encode_mdns_name_new(full_name, mdns_payload)
    mdns_payload += nsec_name                                       # NSEC Name
    mdns_payload += struct.pack('!H', MDNS_NSEC)                    # Type
    mdns_payload += b'\x80\x01'                                     # Class (CF/IN)
    mdns_payload += struct.pack('!I', 4500)                         # ttl

    nsec_bitmap = b'\x00\x05\x00\x00\x80\x00\x40'                   # srv/txt bitmap
    nsec_data_len = struct.pack('!H',len(nsec_name) + len(nsec_bitmap))

    mdns_payload += nsec_data_len                                   # RDATA len
    mdns_payload += encode_mdns_name_new(full_name, mdns_payload)   # NSEC Name
    mdns_payload += nsec_bitmap

    return mdns_payload

def build_eth_header(src_mac: str, dst_mac: str, eth_type: int=0x0800) -> bytes:
    # ethernet header
    src_mac = mac_address_to_bytes(src_mac)
    dst_mac = mac_address_to_bytes(dst_mac)

    return struct.pack("!6s6sH", dst_mac, src_mac, eth_type)

def build_ipv4_header(mdns_len: int, src_ip: str, dst_ip: str) -> bytes:

    ver_hdr_len = 69 # version 4 + header length 20 (5)
    dsf = 0 # DSF
    id = random.randint(0, 0xFFFF)
    payload_len = IP_HEADER_LEN + UDP_HEADER_LEN + mdns_len
    ttl = 255
    ip_proto_udp = 17
    ff_offset = 0x4000
    checksum = 0
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_hdr_len, dsf, payload_len, id, ff_offset,\
        ttl, ip_proto_udp, checksum, src_ip_bytes, dst_ip_bytes)

    calculated_checksum = ip_checksum(header_without_checksum)

    return struct.pack("!BBHHHBBH4s4s", ver_hdr_len, dsf, payload_len, id, ff_offset, ttl, ip_proto_udp, calculated_checksum, src_ip_bytes, dst_ip_bytes)

def build_ipv6_header(mdns_len: int, src_ip: str, dst_ip: str) -> bytes:

    version = 6 << 28
    traffic_class = 0 << 20
    flow_label = 0xd0200
    payload_len = UDP_HEADER_LEN + mdns_len
    next_header = socket.IPPROTO_UDP
    hop_limit = 255

    src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_ip_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)

    return struct.pack("!4sHBB16s16s", struct.pack("!I", version | (traffic_class << 20) | flow_label), payload_len, next_header, hop_limit, src_ip_bytes, dst_ip_bytes)

def build_udp_header(mdns_len: int, mdns_payload: bytes, src_ip: str, dst_ip: str) -> bytes:

    udp_payload_len = UDP_HEADER_LEN + mdns_len
    udp_header = create_udp_header(5353, 5353, udp_payload_len, 0)
    checksum = udp_checksum(src_ip, dst_ip, udp_payload_len, udp_header, mdns_payload)
    
    return create_udp_header(5353, 5353, udp_payload_len, checksum)

def send_spotify_response(resp: ResponseObject):

    service_name = resp.service
    src_mac = resp.src_mac
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    srv_port = resp.srv_port
    hostname = resp.hostname
    ip_version = resp.type_
    is_unicast = resp.unicast
    NO_IPV6 = 0

    domain_name = hostname + '.local'
    full_name = SHA1_HASH + '.' + service_name
    name_field = service_name
    ################ BUILD MDNS PAYLOAD ##################
    mdns_payload = b''

    additional_rrs = 6 if is_unicast == 0 else 4

    if not src_ipv6:
        NO_IPV6 = 1
        additional_rrs -= 1

    mdns_payload = build_mdns_header(mdns_payload, 0x8400, 1, additional_rrs)

    mdns_payload = build_ptr_record(mdns_payload, name_field, full_name)

    mdns_payload = build_a_record(mdns_payload, domain_name, src_ip)

    if src_ipv6:
        mdns_payload = build_aaaa_record(mdns_payload, domain_name, src_ipv6)

    mdns_payload = build_txt_record(mdns_payload, full_name, SPOTIFY)

    mdns_payload = build_srv_record(mdns_payload, full_name, domain_name, srv_port)

    if is_unicast == 0:
        mdns_payload = build_nsec_a_aaaa_record(mdns_payload, domain_name, NO_IPV6)
        mdns_payload = build_nsec_srv_txt_record(mdns_payload, full_name)

    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        dst_mac = MULTICAST_MAC if is_unicast == 0 else resp.dst_mac
        eth_header = build_eth_header(src_mac, dst_mac)

        # ip header
        dst_ip = MULTICAST_IP if is_unicast == 0 else resp.dst_ip
        ip_header = build_ipv4_header(mdns_len, src_ip, dst_ip)        
        
        # udp header
        udp_header = build_udp_header(mdns_len, mdns_payload, src_ip, dst_ip)

    elif ip_version == 6 and src_ipv6:
        # ethernet header
        dst_mac = IPV6_MULTICAST_MAC if is_unicast == 0 else resp.dst_mac
        eth_header = build_eth_header(src_mac, dst_mac, eth_type=0x86dd)

        # ip header
        dst_ip = IPV6_MULTICAST_IP if is_unicast == 0 else resp.dst_ip
        ip_header = build_ipv6_header(mdns_len, src_ipv6, dst_ip)

        udp_header = build_udp_header(mdns_len, mdns_payload, src_ipv6, dst_ip)

    else:
        return None

    return eth_header + ip_header + udp_header + mdns_payload

def send_airplay_response(resp: ResponseObject, type_):
    hostname = resp.hostname
    service_name = resp.service
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    src_mac = resp.src_mac
    srv_port = resp.srv_port
    ip_version = resp.type_
    is_unicast = resp.unicast
    NO_IPV6 = 0

    if '_googlecast._tcp.local' in service_name:
        service_name = '_googlecast._tcp.local'

    top_level_name = hostname
    domain_name = hostname + '.local'
    full_name = top_level_name + '.' + service_name #+ '.local'
    name_field = service_name

    mdns_payload = b''

    additional_rrs = 6 if is_unicast == 0 else 4

    if not src_ipv6:
        NO_IPV6 = 1
        additional_rrs -= 1

    mdns_payload = build_mdns_header(mdns_payload, 0x8400, 1, additional_rrs)

    mdns_payload = build_ptr_record(mdns_payload, name_field, full_name)

    mdns_payload = build_txt_record(mdns_payload, full_name, type_, src_mac, hostname)

    mdns_payload = build_srv_record(mdns_payload, full_name, domain_name, srv_port)

    mdns_payload = build_a_record(mdns_payload, domain_name, src_ip)

    if src_ipv6:
        mdns_payload = build_aaaa_record(mdns_payload, domain_name, src_ipv6)

    if is_unicast == 0:
        mdns_payload = build_nsec_a_aaaa_record(mdns_payload, domain_name, NO_IPV6)
        mdns_payload = build_nsec_srv_txt_record(mdns_payload, full_name)

    ################ BUILD MDNS PAYLOAD ##################
    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        dst_mac = MULTICAST_MAC if is_unicast == 0 else resp.dst_mac
        eth_header = build_eth_header(src_mac, dst_mac)

        # ip header
        dst_ip = MULTICAST_IP if is_unicast == 0 else resp.dst_ip
        ip_header = build_ipv4_header(mdns_len, src_ip, dst_ip)        
        
        # udp header
        udp_header = build_udp_header(mdns_len, mdns_payload, src_ip, dst_ip)

    elif ip_version == 6 and src_ipv6:
        # ethernet header
        dst_mac = IPV6_MULTICAST_MAC if is_unicast == 0 else resp.dst_mac
        eth_header = build_eth_header(src_mac, dst_mac, eth_type=0x86dd)

        # ip header
        dst_ip = IPV6_MULTICAST_IP if is_unicast == 0 else resp.dst_ip
        ip_header = build_ipv6_header(mdns_len, src_ipv6, dst_ip)

        udp_header = build_udp_header(mdns_len, mdns_payload, src_ipv6, dst_ip)

    else:
        return None

    return eth_header + ip_header + udp_header + mdns_payload

def send_query(resp: ResponseObject):
    service_name = resp.service
    src_ip = resp.src_ip
    src_ipv6 = resp.src_ipv6
    src_mac = resp.src_mac
    ip_version = resp.type_

    name_field = encode_mdns_name(service_name)

    mdns_payload = b''

    mdns_payload = build_mdns_header(mdns_payload, 0x8400, 0, 0, 1)

    mdns_payload = build_ptr_record(mdns_payload, name_field, None)

    mdns_len = len(mdns_payload)

    if ip_version == 4:
        # ethernet header
        eth_header = build_eth_header(src_mac, MULTICAST_MAC)

        # ip header
        dst_ip = MULTICAST_IP
        ip_header = build_ipv4_header(mdns_len, src_ip, dst_ip)        
        
        # udp header
        udp_header = build_udp_header(mdns_len, mdns_payload, src_ip, dst_ip)

    elif ip_version == 6 and src_ipv6:
        # ethernet header
        dst_mac = IPV6_MULTICAST_MAC
        eth_header = build_eth_header(src_mac, dst_mac, eth_type=0x86dd)

        # ip header
        dst_ip = IPV6_MULTICAST_IP
        ip_header = build_ipv6_header(mdns_len, src_ipv6, dst_ip)

        udp_header = build_udp_header(mdns_len, mdns_payload, src_ipv6, dst_ip)

    else:
        return None

    return eth_header + ip_header + udp_header + mdns_payload

"""

    if 'google' in service_name:
        

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