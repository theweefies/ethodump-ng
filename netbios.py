#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import List
from io import BytesIO
import struct
import socket

from globals import Client

QUERY                   = 0
ANSWER                  = 1

SERVER_SERVICE          = '<20>'
MASTER_BROWSER          = '<1b>'
LOCAL_MASTER_BROWSER    = '<1d>'
DOMAIN_CONTROLLER       = '<1c>'
MAIL_SLOT               = '<00>'

MSBROWSE                = 'MSBROWSE'

DOMAIN_ANNOUNCEMENT     = 0x0C
UNIQUE_NAME             = 0x20
GROUP_NAME              = 0x1C

SMB1_SERVER_COMPONENT   = b'\xff\x53\x4d\x42'
SMB2_3_SERVER_COMPONENT = b'\xff\x53\x4d\x42'

TRANSACTION_REQUEST    = b'\x25'

@dataclass
class NetBIOSQuery:
    name: str
    type_: int
    class_: int
    control_code: str

@dataclass
class NetBIOSNameRecord:
    name: str
    type_: int
    class_: int
    ttl: int
    data_length: int
    flags: int
    address: str

@dataclass
class NetBIOSResponse:
    transaction_id: int
    flags: int
    questions: int
    answers: int
    name_records: List[NetBIOSNameRecord] = field(default_factory=list)

@dataclass
class NetBIOSDatagram:
    msg_type: int
    flags: int
    datagram_id: int
    src_ip: str
    src_port: int
    packet_offset: int
    src_name: str
    dst_name: str
    blocks: list

@dataclass
class SMBHeader:
    server_component: bytes
    command: int
    error_class: int
    reserved: int
    error_code: int
    flags: int
    flags2: int
    process_id_high: int
    signature: bytes
    reserved2: int
    tree_id: int
    process_id: int
    user_id: int
    multiplex_id: int

@dataclass
class SMBTrxRequest:
    word_count: int
    total_param_count: int
    total_data_count: int
    max_param_count: int
    max_data_count: int
    max_setup_count: int
    trx_reserved: int
    trx_flags: int
    timeout: int
    trx_reserved2: int
    param_count: int
    param_offset: int
    data_count: int
    data_offset: int
    setup_count: int
    trx_reserved3: int
    byte_count: int
    transaction_name: str

@dataclass
class SMBMailslot:
    opcode: int
    priority: int
    class_: int
    size: int
    mailslot_name: str

@dataclass
class MSFWindowsBrowser:
    command: int
    update_count: int
    update_period: int
    hostname: str
    os_major: int
    os_minor: int
    server_type: int
    browser_major: int
    browser_minor: int
    signature: int
    host_comment: str

@dataclass
class NBNSHeader:
    id: int
    flags: int
    message_type: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class NBNSPacket:
    header: NBNSHeader
    questions: list
    answers: list
    authorities: list
    additionals: list

def format_and_clean_netbios_name(name: str) -> tuple[str, str]:
    """
    Function to format and clean netbios names.
    """
    # Check if the last character is a control character or non-printable
    if name and (ord(name[-1]) < 0x21 or ord(name[-1]) > 0x7E):
        # Convert the last character to its hex representation, e.g., <1b>
        control_char_formatted = f'<{ord(name[-1]):02x}>'
        # Remove the control character from the name and strip trailing whitespace
        cleaned_name = name[:-1].rstrip()
    else:
        control_char_formatted = ''
        cleaned_name = name.rstrip()

    # Append formatted control character if it was found
    return cleaned_name, control_char_formatted

def decode_netbios_name(encoded_name: bytes): # -> None | tuple[str,str]:
    """
    Decode a NetBIOS name from its 'half-ASCII' encoding.
    """
    decoded_name = ''

    # Ensure that the encoded name is exactly 32 characters
    if len(encoded_name) != 32:
        return None

    # Process each encoded byte pair
    for i in range(0, 32, 2):  # 32 characters total, in steps of 2
        encoded_byte = encoded_name[i:i+2]
        # Debugging: Print the encoded byte pair being processed
        # print(f"Processing encoded byte pair: {encoded_byte}")
        # Convert each pair of characters back to a byte
        decoded_char = chr(((ord(encoded_byte[0]) - ord('A')) << 4) | (ord(encoded_byte[1]) - ord('A')))
        decoded_name += decoded_char

    # This regex matches any character that is not a printable ASCII char excluding space (0x20-0x7E)
    cleaned_name, control_code = format_and_clean_netbios_name(decoded_name)
    # NetBIOS names are space-padded to 16 chars, so strip trailing spaces
    return cleaned_name, control_code

def parse_netbios_record(reader: BytesIO, cur_client: Client, record_type: int=None): # -> None | NetBIOSNameRecord | NetBIOSQuery:
    """
    Function to parse a netbios record.
    """
    name = reader.read(34)
    if len(name) < 34:
        return None

    encoded_name = name.decode('ascii').strip()[:32]
    decoded_name, control_code = decode_netbios_name(encoded_name)

    if record_type == QUERY:
        record_contents = reader.read(4)
        if len(record_contents) < 4:
            return None
        type_, class_ = struct.unpack('!HH', record_contents)
        return NetBIOSQuery(decoded_name, type_, class_, control_code)
    else:
        record_contents = reader.read(12)
        if len(record_contents) < 12:
            return None
        type_, class_, ttl, data_length, flags = struct.unpack('!HHIHH', record_contents)
        address = socket.inet_ntoa(reader.read(4))  # Assuming IPv4 address
        return NetBIOSNameRecord(decoded_name, type_, class_, ttl, data_length, flags, address)

def parse_netbios_header(reader: BytesIO) -> NBNSHeader:
    """
    Function to parse a netbios packet header.
    """
    # Read and parse the NetBIOS response header
    header = reader.read(12)
    if len(header) < 12:
        return None
    
    transaction_id = header[:2]
    flags = header[2:4]
    message_type = struct.unpack('!H', flags)[0] & 0x8000
    questions, answers, authority, additional = struct.unpack('!HHHH', header[4:])

    return NBNSHeader(transaction_id, flags, message_type, questions, answers, authority, additional)

def parse_netbios_packet(data: bytes, cur_client: Client): # -> None | NBNSPacket:
    """
    Function to parse and craft an NBNS dataclass.
    """
    reader = BytesIO(data)
    header = parse_netbios_header(reader)

    if not header:
        return None
    
    # Lets use list comprehensions with a conditional clause to exclude None values
    questions = [record for record in (parse_netbios_record(reader, cur_client, QUERY) for _ in range(header.num_questions)) if record is not None]
    answers = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_answers)) if record is not None]
    authorities = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_authorities)) if record is not None]
    additionals = [record for record in (parse_netbios_record(reader, cur_client) for _ in range(header.num_additionals)) if record is not None]

    return NBNSPacket(header, questions, answers, authorities, additionals)

def process_nbns_packet(packet: NBNSPacket, cur_client: Client) -> None:
    """
    Function to process a parsed NetBIOSDatagram structure.
    """
    if not packet:
        return
    
    # Extract hostnames from the questions
    for question in packet.questions:
        if isinstance(question, NetBIOSQuery):
            cur_client.notes.add(f"query: {question.name.lower()}")
            if question.control_code in [SERVER_SERVICE, MASTER_BROWSER, LOCAL_MASTER_BROWSER]:
                cur_client.services.add(question.name)
            elif question.control_code == DOMAIN_CONTROLLER:
                cur_client.hostnames.add(question.name)

    # Extract details from answers, authorities, and additionals
    records = packet.answers + packet.authorities + packet.additionals
    for record in records:
        if isinstance(record, NetBIOSNameRecord):
            cur_client.hostnames.add(record.name.lower())
            if record.type_ == UNIQUE_NAME:  # NetBIOS unique name
                cur_client.services.add("NetBIOS Service")
            elif record.type_ == GROUP_NAME:  # Group name (e.g., Domain Controllers)
                cur_client.services.add("NetBIOS Group")
            elif MSBROWSE in record.name:
                cur_client.services.add(record.name)
            else:
                cur_client.hostnames.add(record.name)
            if record.address:
                cur_client.dns_names.add(record.address)

    # Add protocols detected
    cur_client.protocols.add("NBNS-UDP-137")

def process_nbns_dg_packet(packet: NetBIOSDatagram, cur_client: Client) -> None:
    """
    Function to process a parsed NetBIOSDatagram structure.
    """
    if not packet:
        return
    
    if not cur_client.ip_address:
        cur_client.ip_address = packet.src_ip

    if packet.src_name:
        tmp_hostname = packet.src_name
        if MAIL_SLOT in packet.src_name:
            tmp_hostname = packet.src_name.replace(MAIL_SLOT,'')
        cur_client.hostnames.add(tmp_hostname)

    if packet.dst_name:
        cur_client.connections.add(packet.dst_name)

    if packet.blocks:
        for block in packet.blocks:
            if isinstance(block, SMBHeader):
                if block.server_component == SMB1_SERVER_COMPONENT:
                    cur_client.protocols.add('SMB')
            elif isinstance(block, MSFWindowsBrowser):
                if block.command != DOMAIN_ANNOUNCEMENT:
                    if block.hostname:
                        tmp_hostname = block.hostname
                        if MAIL_SLOT in block.hostname:
                            tmp_hostname = block.hostname.replace(MAIL_SLOT,'')
                        cur_client.hostnames.add(tmp_hostname)
                    if block.os_major and block.os_minor:
                        cur_client.notes.add(f'os_ver_from_smb: {block.os_major}.{block.os_minor}')
                    if block.browser_major and block.browser_minor:
                        cur_client.notes.add(f'browser_ver_from_smb: {block.browser_major}.{block.browser_minor}')
                    if block.host_comment:
                        cur_client.services.add(block.host_comment)
    cur_client.protocols.add("NBNS-UDP-138")

def parse_netbios_datagram(data: bytes):
    """
    Function to parse NBNS Datagram packets.
    """
    reader = BytesIO(data)
    data = reader.read(4)
    if len(data) < 4:
        return None
    message_type, flags, datagram_id = struct.unpack('!BBH', data)
    data = reader.read(4)
    if len(data) < 4:
        return None
    src_ip = socket.inet_ntoa(data)
    data = reader.read(6)
    if len(data) < 6:
        return None
    src_port, datagram_len, pkt_offset = struct.unpack('!HHH', data)
    name = reader.read(34)
    if len(name) < 34:
        return None

    encoded_src_name = name.decode('ascii').strip()[:32]
    decoded_src_name, src_ctrl_code = decode_netbios_name(encoded_src_name)
    src_name = decoded_src_name + src_ctrl_code

    name = reader.read(34)
    if len(name) < 34:
        return None
    
    encoded_dst_name = name.decode('ascii').strip()[:32]
    decoded_dst_name, dst_ctrl_code = decode_netbios_name(encoded_dst_name)
    dst_name = decoded_dst_name + dst_ctrl_code

    blocks = []
    data = reader.read(4)
    if len(data) < 4:
        return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, blocks)
    
    smb_header = None
    transaction_request = None

    # Additional checks and parsing for SMB Header and Trans Request
    if data == SMB1_SERVER_COMPONENT:
        # SMB Header
        smb_header_fmt = '!BBBHBHH8sHHHHH'
        smb_header_len = struct.calcsize(smb_header_fmt)
        smb_header_data = reader.read(smb_header_len)
        
        if len(smb_header_data) < smb_header_len:
            return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, ["Malformed SMB Header"])

        (command, error_class, reserved, error_code, smb_flags, smb_flags2, 
         process_id_high, signature, reserved2, tree_id, process_id, 
         user_id, multiplex_id) = struct.unpack(smb_header_fmt, smb_header_data)

        smb_header = SMBHeader(SMB1_SERVER_COMPONENT, command, error_class, reserved, error_code, smb_flags,\
                               smb_flags2, process_id_high, signature, reserved2, tree_id, process_id, user_id, multiplex_id)

        # SMB Trans Request parsing
        if command == 0x25:  # Trans Command
            trans_req_fmt = '<BHHHHBBHIHHHHHBB'
            trans_req_len = struct.calcsize(trans_req_fmt)
            trans_req_data = reader.read(trans_req_len)

            if len(trans_req_data) < trans_req_len:
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, [smb_header])

            (word_count, total_param_count, total_data_count, max_param_count,
             max_data_count, max_setup_count, trx_reserved, trx_flags, timeout, trx_reserved2,
             param_count, param_offset, data_count, data_offset, setup_count,
             trx_reserved3) = struct.unpack(trans_req_fmt, trans_req_data)

            mailslot_fmt = '<HHHH'
            mailslot_len = struct.calcsize(mailslot_fmt)
            mailslot_data = reader.read(mailslot_len)

            if len(mailslot_data) < mailslot_len:
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, [smb_header])
            
            opcode, priority, class_, size = struct.unpack(mailslot_fmt, mailslot_data)

            byte_count = size

            mailslot_name_encoded = reader.read(word_count)
            mailslot_name = mailslot_name_encoded[:-1].decode('utf-8', 'ignore')
            transaction_name = mailslot_name
            
            transaction_request = SMBTrxRequest(word_count, total_param_count, total_data_count, max_param_count, max_data_count,\
                                                max_setup_count, trx_reserved, trx_flags, timeout, trx_reserved2, param_count,\
                                                param_offset, data_count, data_offset, setup_count, trx_reserved3, byte_count,\
                                                transaction_name)

            mailslot_header = SMBMailslot(opcode, priority, class_, size, mailslot_name)

            msfwb_proto_data = reader.read(data_count)
            if len(msfwb_proto_data) < data_count or data_count == 0:
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, \
                                       [smb_header, transaction_request, mailslot_header])
            
            msfwb_command = msfwb_proto_data[0]
            if msfwb_command in [0x01, 0x0c, 0x0f]:   # Host Announcement, domain/workgroup announcement, local master announcement
                update_count, update_period = struct.unpack('<BI', msfwb_proto_data[1:6])
                 # Assuming the hostname is always padded to 16 bytes, we directly slice it
                hostname_encoded = msfwb_proto_data[6:22]  # Slice out the hostname, assuming fixed 16-byte padding
                hostname = hostname_encoded.decode('utf-8', 'ignore').rstrip('\x00')  # Remove any null byte padding from the decoded hostname
                
                # The version info starts immediately after the 16-byte hostname
                version_info = msfwb_proto_data[22:]

                windows_major = version_info[0]
                windows_minor = version_info[1]
                server_type = struct.unpack('<I', version_info[2:6])[0]
                browser_major = version_info[6]
                browser_minor = version_info[7]
                browser_signature = version_info[8:10]
                
                # Decode the remaining bytes for the host comment, ensuring to ignore any trailing null bytes
                host_comment = version_info[10:].decode('utf-8', 'ignore').rstrip('\x00')
                msft_windows_browser_header = MSFWindowsBrowser(msfwb_command, update_count, update_period, hostname,\
                                        windows_major, windows_minor, server_type, browser_major, browser_minor,\
                                        browser_signature, host_comment)
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, \
                                       [smb_header, transaction_request, mailslot_header, msft_windows_browser_header])
            
            elif msfwb_command == 0x09: # Get Backup List Request
                backup_list_req_count, backup_req_token = struct.unpack('<BI', msfwb_proto_data[1:6])
                msft_windows_browser_header = (msfwb_command, backup_list_req_count, backup_req_token)
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, \
                                       [smb_header, transaction_request, mailslot_header, msft_windows_browser_header])
            else:
                return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, \
                                       [smb_header, transaction_request, mailslot_header])
        else:
            return NetBIOSDatagram(message_type, flags, datagram_id, src_ip, src_port, pkt_offset, src_name, dst_name, [smb_header])


