#!/usr/bin/env python3

"""
TCP, UDP, IPv4 and IPv6 dataclass, parsing & processing
module for ethodump-ng 
"""

import struct
import socket
from dataclasses import dataclass
from io import BytesIO
import sys
import json
import time
import zipfile
import pkgutil

os_sample_count = {}

ALLOWED_IP = None
SPAN_TREE = b'\x01\x80\xc2\x00\x00\x00'

if sys.version_info < (3,):
    compat_ord = ord
else:
    def compat_ord(char):
        return char

from globals import bytes_to_mac, bytes_to_ip, bytes_to_ipv6, tcp_fp_dbase_list, tcp_fps

# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0  # end of option list
TCP_OPT_NOP = 1  # no operation
TCP_OPT_MSS = 2  # maximum segment size
TCP_OPT_WSCALE = 3  # window scale factor, RFC 1072
TCP_OPT_SACKOK = 4  # SACK permitted, RFC 2018
TCP_OPT_SACK = 5  # SACK, RFC 2018
TCP_OPT_ECHO = 6  # echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY = 7  # echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP = 8  # timestamp, RFC 1323
TCP_OPT_POCONN = 9  # partial order conn, RFC 1693
TCP_OPT_POSVC = 10  # partial order service, RFC 1693
TCP_OPT_CC = 11  # connection count, RFC 1644
TCP_OPT_CCNEW = 12  # CC.NEW, RFC 1644
TCP_OPT_CCECHO = 13  # CC.ECHO, RFC 1644
TCP_OPT_ALTSUM = 14  # alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA = 15  # alt checksum data, RFC 1146
TCP_OPT_SKEETER = 16  # Skeeter
TCP_OPT_BUBBA = 17  # Bubba
TCP_OPT_TRAILSUM = 18  # trailer checksum
TCP_OPT_MD5 = 19  # MD5 signature, RFC 2385
TCP_OPT_SCPS = 20  # SCPS capabilities
TCP_OPT_SNACK = 21  # selective negative acks
TCP_OPT_REC = 22  # record boundaries
TCP_OPT_CORRUPT = 23  # corruption experienced
TCP_OPT_SNAP = 24  # SNAP
TCP_OPT_TCPCOMP = 26  # TCP compression filter
TCP_OPT_MAX = 27
# User Timeout Option (also, other known unauthorized use) [***][1]	[RFC5482]
TCP_OPT_USRTO = 28
TCP_OPT_AUTH = 29  # TCP Authentication Option (TCP-AO)	[RFC5925]
TCP_OPT_MULTIPATH = 30  # Multipath TCP (MPTCP)
TCP_OPT_FASTOPEN = 34  # TCP Fast Open Cookie	[RFC7413]
TCP_OPY_ENCNEG = 69  # Encryption Negotiation (TCP-ENO)	[RFC8547]
# RFC3692-style Experiment 1 (also improperly used for shipping products)
TCP_OPT_EXP1 = 253
# RFC3692-style Experiment 2 (also improperly used for shipping products)
TCP_OPT_EXP2 = 254

@dataclass
class ETHHeader:
    dst_mac: str
    src_mac: str
    eth_type: bytes

@dataclass
class IPHeader:
    version: int
    header_length: int
    differentiated_service_field: int
    total_length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    options: bytes

@dataclass
class IPv6Header:
    verison: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ipv6: str
    dst_ipv6: str

@dataclass
class TCPHeader:
    syn_set: int
    src_port: int
    dst_port: int
    sequence_num: int
    acknowledgement_num: int
    header_length: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    payload_length: int
    options:bytes

@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: bytes
    payload_length: int

@dataclass
class SPANNINGTreePacket:
    dst_mac: str
    src_mac: str
    length: int
    llc_dsap: int
    llc_ssap: int
    llc_ctrl_field: int
    proto_id: int
    proto_ver_id: int
    bpdu_type: int
    bpdu_flags: int
    root_bridge_pri: int
    root_bridge_system_id_ext: int
    root_bridge_system_id: str
    root_path_cost: int
    bridge_priority: int
    bridge_system_id_ext: int
    bridge_system_id: str
    port_id: int
    message_age: int
    max_age: int
    hello_time: int
    forward_delay: int

"""
NOTE: TCP FINGERPRINT FUNCTIONS
"""

def load_tcp_fp_dbase(running_pyz: bool):
    global tcp_fp_dbase_list

    if running_pyz:
        print('[+] Running from a .pyz archive, loading from archive...')
        # Load the JSON directly from the archive
        try:
            data = pkgutil.get_data(__name__, 'tcp_fp_db.json')
            tcp_fp_dbase_list = json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f'[!] Failed to load tcp_fp_db.json from the archive: {e}')
            sys.exit(1)
    else:
        # Fall back to loading from the filesystem
        print('[+] Loading tcp fingerprint database from file system...')
        databaseFile = 'tcp_fp_db.json'
        try:
            with open(databaseFile) as f:
                tcp_fp_dbase_list = json.load(f)
        except FileNotFoundError:
            print(f'[!] Could not find {databaseFile} on the filesystem.')
            sys.exit(1)    
    
    for el in tcp_fp_dbase_list:
        if el['os'] not in os_sample_count:
            os_sample_count[el['os']] = 0
        os_sample_count[el['os']] += 1

def parse_opts(buf):
    """Parse TCP option buffer into a list of (option, data) tuples."""
    opts = []
    while buf:
        o = compat_ord(buf[0])
        if o > TCP_OPT_NOP:
            try:
                # advance buffer at least 2 bytes = 1 type + 1 length
                l = max(2, compat_ord(buf[1]))
                d, buf = buf[2:l], buf[l:]
            except (IndexError, ValueError):
                opts.append(None)  # XXX
                break
        else:
            # options 0 and 1 are not followed by length byte
            d, buf = b'', buf[1:]
        opts.append((o, d))
    return opts

def decode_tcp_options(opts):
    """
    Decodes TCP options into a readable string.

    [(2, b'\x05\xb4'), (1, b''), (3, b'\x06'), (1, b''), (1, b''),
      (8, b'3.S\xa8\x00\x00\x00\x00'), (4, b''), (0, b''), (0, b'')]
    """
    str_opts = ''
    mss = 0
    timestamp_echo_reply = ''
    timestamp = ''
    window_scaling = None

    for opt in opts:
        option_type, option_value = opt
        if option_type == TCP_OPT_EOL:  # End of options list
            str_opts = str_opts + 'E,'
        elif option_type == TCP_OPT_NOP:  # No operation
            str_opts = str_opts + 'N,'
        elif option_type == TCP_OPT_MSS:  # Maximum segment size
            try:
                mss = struct.unpack('!h', option_value)[0]
                str_opts = str_opts + 'M' + str(mss) + ','
            except Exception as e:
                pass
        elif option_type == TCP_OPT_WSCALE:  # Window scaling
            window_scaling = struct.unpack('!b', option_value)[0]
            str_opts = str_opts + 'W' + str(window_scaling) + ','
        elif option_type == TCP_OPT_SACKOK:  # Selective Acknowledgement permitted
            str_opts = str_opts + 'S,'
        elif option_type == TCP_OPT_SACK:  # Selective ACKnowledgement (SACK)
            str_opts = str_opts + 'K,'
        elif option_type == TCP_OPT_ECHO:
            str_opts = str_opts + 'J,'
        elif option_type == TCP_OPT_ECHOREPLY:
            str_opts = str_opts + 'F,'
        elif option_type == TCP_OPT_TIMESTAMP:
            try:
                str_opts = str_opts + 'T,'
                timestamp = struct.unpack('!I', option_value[0:4])[0]
                timestamp_echo_reply = struct.unpack(
                    '!I', option_value[4:8])[0]
            except Exception as e:
                pass
        elif option_type == TCP_OPT_POCONN:
            str_opts = str_opts + 'P,'
        elif option_type == TCP_OPT_POSVC:
            str_opts = str_opts + 'R,'
        else:  # unknown TCP option. Just store the opt_type
            str_opts = str_opts + 'U' + str(option_type) + ','

    return (str_opts, timestamp, timestamp_echo_reply, mss, window_scaling)

def score_fp(fp):
    """The most recent version of TCP/IP fingerprint scoring algorithm.

    Args:
        fp (dict): The fingerprint to score

    Returns:
        avg_os_score: average score of this fingerprint for all OS
    """
    global tcp_fp_dbase_list

    if not tcp_fp_dbase_list:
        return None
    
    # Hardcoded for performance reasons
    os_scores = {
        'Android': 0,
        'Windows': 0,
        'Mac OS': 0,
        'iOS': 0,
        'Linux': 0
    }
    for entry in tcp_fp_dbase_list:
        score = 0
        os_name = entry['os']
        if entry['ip_id'] == fp['ip_id']:
            score += 1.5
        if entry['ip_tos'] == fp['ip_tos']:
            score += 0.25
        if entry['ip_total_length'] == fp['ip_total_length']:
            score += 2.5
        if entry['ip_ttl'] == fp['ip_ttl']:
            score += 2
        if entry['tcp_off'] == fp['tcp_off']:
            score += 2.5
        if entry['tcp_timestamp_echo_reply'] == fp['tcp_timestamp_echo_reply']:
            score += 2
        if entry['tcp_window_scaling'] == fp['tcp_window_scaling']:
            score += 2
        if entry['tcp_window_size'] == fp['tcp_window_size']:
            score += 2
        if entry['tcp_flags'] == fp['tcp_flags']:
            score += 0.25
        if entry['tcp_mss'] == fp['tcp_mss']:
            score += 1.5
        if entry['tcp_options'] == fp['tcp_options']:
            score += 4
        elif entry['tcp_options_ordered'] == fp['tcp_options_ordered']:
            score += 2.5
        os_scores[os_name] += score

    avg_os_score = {}
    for os_name in os_scores:
        avg_os_score[os_name] = round(
            os_scores[os_name] / os_sample_count[os_name], 2)

    return avg_os_score

def tcp_ip_fingerprint(pkt, ip_header: IPHeader, tcp_header: TCPHeader, cur_client) -> None:
    """
    Function to prepare tcp/ip fingerprint from SYN frame
    """
    epoch_time = str(time.time())
    seconds, microseconds = int(epoch_time.split(".")[0]), int(epoch_time.split(".")[1])
    flags = tcp_header.flags
    ip_flags = ip_header.flags

    # IP Header flag parsing
    rf = (ip_flags & 0x80) >> 7
    dnf = (ip_flags & 0x40) >> 6
    mfs = (ip_flags & 0x20) >> 5
    # TCP Header flag parsing
    res = (flags & 0x0e00) >> 9
    nonce = (flags & 0x0100) >> 8
    cwr = (flags & 0x0080) >> 7
    ecn = (flags & 0x0040) >> 6
    urg = (flags & 0x0020) >> 5
    ack = (flags & 0x0010) >> 4
    psh = (flags & 0x0008) >> 3
    rst = (flags & 0x0004) >> 2
    syn = (flags & 0x0002) >> 1
    fin = flags & 0x0001

    if syn and not ack:

        if tcp_header.options:
            tcp_options = parse_opts(tcp_header.options)

            [str_opts, timestamp, timestamp_echo_reply, mss,
                window_scaling] = decode_tcp_options(tcp_options)
        
        cap_len = len(pkt)
        dst_ip = ip_header.dst_ip
        dst_port = tcp_header.dst_port
        header_len = None
        ip_checksum = ip_header.checksum
        ip_df = dnf
        ip_hdr_len = ip_header.header_length // 4
        ip_id = 0 if ip_header.identification == 0 else 1
        ip_mf = mfs
        ip_nxt = None # IPv6
        ip_off = ip_header.frag_offset
        ip_plen = None # IPv6
        ip_protocol = ip_header.protocol
        ip_rf = rf
        ip_tos = ip_header.differentiated_service_field
        ip_total_length = ip_header.total_length
        ip_ttl = ip_header.ttl
        ip_version = ip_header.version
        src_ip = ip_header.src_ip
        src_port = tcp_header.src_port
        tcp_ack = ack
        tcp_checksum = tcp_header.checksum
        tcp_flags = flags
        tcp_header_len = tcp_header.header_length
        tcp_mss = mss
        tcp_off = None
        tcp_options = str_opts
        tcp_options_ordered = ''.join(
                    [e[0] for e in str_opts.split(',') if e])
        tcp_seq = tcp_header.sequence_num
        tcp_timestamp = 0 if not timestamp else 1
        tcp_timestamp_echo_reply = 0 if not timestamp_echo_reply else 1
        tcp_urp = tcp_header.urgent_pointer
        tcp_window_scaling = window_scaling
        tcp_window_size = tcp_header.window_size
        
        tcp_fp = {
        'cap_len':cap_len,
        'dst_ip':dst_ip, 
        'dst_port':dst_port, 
        'header_len':header_len, 
        'ip_checksum':ip_checksum,
        'ip_df':ip_df, 
        'ip_hd_len':ip_hdr_len, 
        'ip_id':ip_id,
        'ip_mf':ip_mf, 
        'ip_nxt':ip_nxt,
        'ip_off':ip_off,
        'ip_len':ip_plen,
        'ip_protocol':ip_protocol,
        'ip_rf':ip_rf,
        'ip_tos':ip_tos,
        'ip_total_length':ip_total_length,
        'ip_ttl':ip_ttl,
        'ip_version':ip_version,
        'src_ip':src_ip,
        'src_port':src_port,
        'tcp_ack':tcp_ack,
        'tcp_checksum':tcp_checksum,
        'tcp_flags':tcp_flags,
        'tcp_header_len':tcp_header_len,
        'tcp_mss':tcp_mss,
        'tcp_off':tcp_off,
        'tcp_options':tcp_options,
        'tcp_options_ordered':tcp_options_ordered,
        'tcp_seq':tcp_seq,
        'tcp_timestamp':tcp_timestamp,
        'tcp_timestamp_echo_reply':tcp_timestamp_echo_reply,
        'tcp_urp':tcp_urp,
        'tcp_window_scaling':tcp_window_scaling,
        'tcp_window_size':tcp_window_size,
        'ts':[seconds,microseconds]
        }
        
        if not tcp_fps.get(src_ip, None):
            tcp_fps[src_ip] = []
        cur_fp = tcp_fps.get(src_ip, None)
        cur_fp.append(tcp_fp)

        os_score = score_fp(tcp_fp)
        if os_score:
            cur_client.fingerprints["tcp"] = os_score


"""
NOTE: PACKET CREATION FUNCTIONS
"""

def create_ipv6_pseudo_header(src_ip, dst_ip, payload_len, next_header):
    try:
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    except OSError as e:
        return None
    return struct.pack('!16s16sI3xB', src_ip_bytes, dst_ip_bytes, payload_len, next_header)

def udp_ipv6_checksum(src_ip, dest_ip, udp_len, udp_header, payload):
    pseudo_header = create_ipv6_pseudo_header(src_ip, dest_ip, udp_len, socket.IPPROTO_UDP)
    if len(payload) % 2:
        payload += b'\0'
    return ip_checksum(pseudo_header + udp_header + payload)

def ip_checksum(ip_header):
    assert len(ip_header) % 2 == 0, "Header length must be even."

    checksum = 0
    for i in range(0, len(ip_header), 2):
        word = (ip_header[i] << 8) + ip_header[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff

def udp_checksum(src_addr, dest_addr, udp_length, udp_header, udp_data):
    """
    Calculate the UDP checksum including the pseudo-header.
    """
    # Pseudo-header fields
    protocol = 17  # UDP protocol number
    pseudo_header = struct.pack('!4s4sBBH', 
                                socket.inet_aton(src_addr), 
                                socket.inet_aton(dest_addr), 
                                0, 
                                protocol, 
                                udp_length)

    # Calculate the checksum including pseudo-header
    checksum = 0
    # Process the pseudo-header
    for i in range(0, len(pseudo_header), 2):
        word = (pseudo_header[i] << 8) + pseudo_header[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # Process the UDP header
    for i in range(0, len(udp_header), 2):
        word = (udp_header[i] << 8) + udp_header[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # Process the data
    if len(udp_data) % 2:  # if odd length, pad with a zero byte
        udp_data += b'\x00'
    for i in range(0, len(udp_data), 2):
        word = (udp_data[i] << 8) + udp_data[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff

def create_udp_header(src_port, dst_port, length, checksum):
    
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)

# Calculate the checksum
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff
   
"""
NOTE: PACKET PARSING FUNCTIONS
"""

def parse_spanning_tree(data: bytes, reader: BytesIO) -> SPANNINGTreePacket | None:

    dst_mac_bytes, src_mac_bytes, length = struct.unpack('!6s6s2s', data)
    dst_mac = bytes_to_mac(dst_mac_bytes)
    src_mac = bytes_to_mac(src_mac_bytes)

    llc = reader.read(3)
    if len(llc) < 3:
        return None
    llc_dsap = llc[0]
    llc_ssap = llc[1]
    llc_ctrl_field = llc[2]

    stp_header = reader.read(5)
    if len(stp_header) < 5:
        return None
    proto_id, proto_ver_id, bpdu_type, bpdu_flags = struct.unpack("!HBBB", stp_header)

    root_bridge_element = reader.read(8)
    if len(root_bridge_element) < 8:
        return None
    root_bridge_system_id_ext = root_bridge_element[1]
    root_bridge_pri, root_bridge_system_id = struct.unpack("!H6s", root_bridge_element)
    root_bridge_system_id = bytes_to_mac(root_bridge_system_id)

    root_path_cost = reader.read(1)
    if len(root_path_cost) < 1:
        return None

    bridge_element = reader.read(8)
    if len(root_bridge_element) < 8:
        return None
    bridge_system_id_ext = bridge_element[1]
    bridge_pri, bridge_system_id = struct.unpack("!H6s", bridge_element)
    bridge_system_id = bytes_to_mac(bridge_system_id)

    footer_data = reader.read(10)
    if len(footer_data) < 10:
        return None
    port_id, message_age, max_age, hello_time, forward_delay = struct.unpack("!HHHHH", footer_data)

    return SPANNINGTreePacket(dst_mac, src_mac, length, llc_dsap, llc_ssap, llc_ctrl_field,\
                            proto_id, proto_ver_id, bpdu_type, bpdu_flags, root_bridge_pri,\
                            root_bridge_system_id_ext, root_bridge_system_id, root_path_cost,\
                            bridge_pri, bridge_system_id_ext, bridge_system_id, port_id,\
                            message_age, max_age, hello_time, forward_delay)

def parse_eth_header(reader: BytesIO) -> ETHHeader | None:
    """
    Ethernet Header Parsing Function
    """
    data = reader.read(14)
    if len(data) < 14:
        return None
    
    if data[:6] == SPAN_TREE:
        span_tree_packet = parse_spanning_tree(data, reader)
        if not span_tree_packet:
            return None
        else:
            return span_tree_packet

    dst_mac_bytes, src_mac_bytes, eth_type = struct.unpack('!6s6s2s', data)
    dst_mac = bytes_to_mac(dst_mac_bytes)
    src_mac = bytes_to_mac(src_mac_bytes)

    return ETHHeader(dst_mac, src_mac, eth_type)

def parse_ip_header(reader: BytesIO) -> IPHeader | None:
    """
    IPv4 Header Parsing Function
    """
    data = reader.read(20)
    if len(data) < 20:
        return None
    ver_len = data[0]
    version = (ver_len & 0xF0) >> 4
    header_length = (ver_len & 0x0F) * 4 # to resolve to the actual number of bytes
    dsf = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = struct.unpack('!H',data[4:6])[0]
    flags = data[6]
    frag_offset = struct.unpack('!H', data[6:8])[0] & 0x1FFF
    ttl = data[8]
    proto = data[9]
    checksum = struct.unpack('!H',data[10:12])[0]
    src_ip = bytes_to_ip(data[12:16])
    dst_ip = bytes_to_ip(data[16:20])
    options = b''
    if header_length > 20:
        options = reader.read(header_length - 20)

    return IPHeader(version, header_length, dsf, total_length, identification, \
                    flags, frag_offset, ttl, proto, checksum, src_ip, dst_ip, options)

def parse_ipv6_header(reader: BytesIO) -> IPv6Header | None:
    """
    IPv6 Header Parsing Function
    """
    data = reader.read(40)
    if len(data) < 40:
        return None
    version = (data[0] & 0xF0) >> 4
    payload_length, next_header, hop_limit = struct.unpack('!HBB', data[4:8])
    src_ipv6 = bytes_to_ipv6(data[8:24])
    dst_ipv6 = bytes_to_ipv6(data[24:40])
    if next_header == 0: # icmpv6
        data = reader.read(8)
        
    return IPv6Header(version, payload_length, next_header,\
                      hop_limit, src_ipv6, dst_ipv6)

def parse_udp_header(reader: BytesIO) -> UDPHeader | None:
    """
    UDP Header Parsing Function
    """
    data = reader.read(8)
    if len(data) < 8:
        return None
    src_port, dst_port, udp_total_len = struct.unpack('!HHH', data[:6])
    checksum = data[6:8]
    udp_payload_len = udp_total_len - 8

    return UDPHeader(src_port, dst_port, udp_total_len, checksum, udp_payload_len)

def parse_tcp_header(reader: BytesIO) -> TCPHeader | None:
    """
    TCP Header Parsing Function
    """
    data = reader.read(20)
    if len(data) < 20:
        return None
    src_port, dst_port, seq_num, ack_num = struct.unpack('!HHII', data[:12])
    header_length = ((data[12] & 0xF0) >> 4) * 4 # to resolve to bytes
    flags = struct.unpack('!H', data[12:14])[0] & 0x0FFF
    syn = (flags & 0x0002) >> 1
    window_size = struct.unpack('!H', data[14:16])[0]
    checksum = struct.unpack('!H',data[16:18])[0]
    urgent_pointer = struct.unpack('!H', data[18:20])[0]
    if header_length > 20:
        data = reader.read(header_length - 20)
        options = data
    else:
        options = b''

    # we set the payload length to 0 because this will be set later -> math ->
    return TCPHeader(syn, src_port, dst_port, seq_num, ack_num, header_length, \
                    flags, window_size, checksum, urgent_pointer, 0, options)