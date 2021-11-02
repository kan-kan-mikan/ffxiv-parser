# Final Fantasy XIV Patch 5.58 global server packet sniffer and parser


import binascii, socket, sys
from enum import Enum
from struct import *


# TCP ports that FFXIV uses
FFXIV_SRC_PORTS = list(range(54992, 54995)) + list(range(55006, 55008)) + list(range(55021, 55041))
FFXIV_PACKET_HEADER_LEN = 40
FFXIV_SEGMENT_HEADER_LEN = 16
FFXIV_IPC_HEADER_LEN = 16


def main():
    # FF14 uses TCP for network traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
   
    while True:
        packet = sock.recvfrom(65565)
        packet = packet[0]

        # process the IP header to isolate the TCP packet
        ip_header = packet[0:20]
        ip_header_len = 4 * (ip_header[0] & 0xF) # clear the version bits and just get 32-bit len, multiply by 4 to convert to byte length

        # process the TCP header to isolate the FFXIV packet
        tcp_header = packet[ip_header_len : ip_header_len + 20]
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        src_port = tcph[0]
        dst_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        data_offset_reserved = tcph[4]
        tcp_header_len = 4 * (data_offset_reserved >> 4) # get 32-bit len and convert to byte length
     
        # decode the packet if it was transmitted over a port FFXIV uses
        if(src_port in FFXIV_SRC_PORTS):
            header_size = ip_header_len + tcp_header_len
            data_size = len(packet) - header_size
            
            # process FFXIV data from the packet if it includes an FFXIV packet, segment, and IPC header
            data = packet[header_size:]

            if(data_size > FFXIV_PACKET_HEADER_LEN + FFXIV_SEGMENT_HEADER_LEN + FFXIV_IPC_HEADER_LEN):
                print(f'''----------------------------------------------------------
                    Source Port: {str(src_port)}
                    Dest Port: {str(dst_port)}
                    Sequence Number: {str(sequence)}
                    Acknowledgement: {str(acknowledgement)}
                    TCP Header Length: {str(tcp_header_len)}
                ''')

                ffxiv_packet_header(data) # decode FFXIV packet header
                segment_type = ffxiv_segment_header(data)[3] # decode FFXIV segment header

                # handle IPC data
                if(segment_type == 3):
                    (_, opcode, _, _, ipc_data) = ffxiv_ipc_header(data) # decode FFXIV IPC header
                   
                    print('OPCODE: ' + opcode)

                    # handle UpdateHpMpTp
                    if(opcode == '0x1a7'):
                        IPC_decode_UpdateHpMpTp(ipc_data)

                    # handle UpdateClassInfo
                    if(opcode == '0x3bf'):
                        IPC_decode_UpdateClassInfo(ipc_data)

                    # handle PublicMessage
                    if(opcode == '0xfe'):
                        IPC_decode_PublicMessage(ipc_data)

                    # handle GroupMessage
                    if(opcode == '0x65'):
                        IPC_decode_GroupMessage(ipc_data)
                    


'''
Decode FFXIV packet headers.

Format:
    16 byte - Magic number ('5252a041ff5d46e27f2a644d7b99c475' in hex, supposedly decodes to FF14ARR)
    8 byte - Timestamp in UNIX time
    2 byte - Packet size
    2 byte - Unknown (always seems to be all 0's, might be padding)
    2 byte - Connection type (only relevant for chat message packets)
    2 byte - Message count
    1 byte - Encoding
    1 byte - Compression flag
    2 byte - Unknown (always seems to be all 0's, might be padding)
    2 byte - Unknown (always seems to be all 0's, might be padding)
    2 byte - Unknown (always seems to be all 0's, might be padding)
'''
def ffxiv_packet_header(data):
    header = data[0:FFXIV_PACKET_HEADER_LEN]
    packet = unpack('<16s8sHHHH??HHH', header)

    magic_num = binascii.hexlify(packet[0])
    timestamp = int.from_bytes(packet[1], byteorder='little')
    connection_type = packet[3]
    message_count = packet[4]
    encoding = packet[5]
    compression = packet[6]

    print(f'''Packet Header: {str(header)}
        Magic Number: {str(magic_num)}
        Timestamp: {str(timestamp)}
        Connection Type: {str(connection_type)}
        Message Count: {str(connection_type)}
        Encoding: {str(encoding)}
        Compression: {str(compression)}
    ''')
    return (magic_num, timestamp, connection_type, message_count, encoding, compression)


'''
Decode FFXIV segment headers.

Format:
    4 byte - Segment size (size of the packet minus the packet header)
    4 byte - Source (gameplay related data)
    4 byte - Target (gameplay related data)
    2 byte - Segment type (all gameplay related ones are type 3 for IPC)
    2 byte - Unknown (always seems to be all 0's, might be padding)
'''
def ffxiv_segment_header(data):
    class Segment_Type(Enum):
        SESSION_INIT = 1
        IPC = 3
        CLIENT_KEEPALIVE = 7
        SERVER_KEEPALIVE = 8
        ENCRYPTION_INIT = 9

    offset_start = FFXIV_PACKET_HEADER_LEN
    offset_end = FFXIV_PACKET_HEADER_LEN + FFXIV_SEGMENT_HEADER_LEN
    header = data[offset_start : offset_end]
    packet = unpack('<LLLHH', header)

    segment_size = packet[0]
    source = packet[1]
    target = packet[2]
    segment_type = packet[3]

    # show segment type with descriptor if it is a known segment type
    segment_type_text = segment_type
    if(segment_type in [item.value for item in Segment_Type]):
        segment_type_text = f'{segment_type} ({Segment_Type(segment_type).name})'

    print(f'''Segment Header: {str(header)}
        Segment Size: {str(segment_size)}
        Source: {str(source)}
        Target: {str(target)}
        Segment Type: {segment_type_text}
    ''')
    return (segment_size, source, target, segment_type)


'''
Decode FFXIV IPC headers. Data appended to this header is the actual game data
that we want to parse.

Format:
    2 byte - Magic number
    2 byte - IPC opcode (identifies what the IPC data is for)
    2 byte - Unknown (always seems to be all 0's, might be padding)
    2 byte - Server ID
    4 byte - Timestamp in UNIX time
    4 byte - Unknown (always seems to be all 0's, might be padding)
'''
def ffxiv_ipc_header(data):
    offset_start = FFXIV_PACKET_HEADER_LEN + FFXIV_SEGMENT_HEADER_LEN
    offset_end = FFXIV_PACKET_HEADER_LEN + FFXIV_SEGMENT_HEADER_LEN + FFXIV_IPC_HEADER_LEN
    header = data[offset_start : offset_end]
    packet = unpack('<HHHHLL', header)

    magic_num = packet[0]
    opcode = hex(packet[1])
    server_id = packet[3]
    timestamp = packet[4]
    ipc_data = data[offset_end:]

    # show opcode with descriptor if it is a known opcode
    opcode_text = opcode
    if(str(opcode) == '0x1a7'):
        opcode_text = f'{opcode} (UpdateHpMpTp)'
    if(str(opcode) == '0xfe'):
        opcode_text = f'{opcode} (PublicMessage)'

    print(f'''IPC Header: {str(header)}
        Magic Number: {str(magic_num)}
        Opcode: {opcode_text}
        Server ID: {str(server_id)}
        Timestamp: {str(timestamp)}
        IPC Data: {str(ipc_data)}
    ''')
    return (magic_num, opcode, server_id, timestamp, ipc_data)


'''
Decode FFXIV IPC data for opcode 0x01a7 (UpdateHpMpTp). This opcode handles
updating player health, mana, and tactical point regeneration. Tactical points
have not been used in the game since Patch 5.0.

Format:
    4 byte - HP
    2 byte - MP
    2 byte - TP (random data that isn't used anymore)
'''
def IPC_decode_UpdateHpMpTp(data):
    data = data[:8]
    packet = unpack('<LHH', data)

    hp = packet[0]
    mp = packet[1]

    print(f'''UpdateHpMpTp:
        Health: {str(hp)}
        Mana: {str(mp)}
    ''')
    return (hp, mp)


'''
Decode FFXIV IPC data for opcode 0x03bf (UpdateClassInfo). This opcode handles
the character's currently equipped class, level, and experience points.

Format:
    1 byte - ClassID (this list isn't reverse engineered)
    1 byte - Level1
    2 byte - Current level
    4 byte - Next level index
    4 byte - Current experience
    4 byte - Rested experience (amount of bonus experience that can be gained currently)
'''
def IPC_decode_UpdateClassInfo(data):
    data = data[:16]
    packet = unpack('<BBHLLL', data)

    class_id = packet[0]
    level1 = packet[1]
    current_level = packet[2]
    next_level_index = packet[3]
    current_exp = packet[4]
    rested_exp = packet[5]

    print(f'''UpdateClassInfo:
        Class ID: {str(class_id)}
        Level1: {str(level1)}
        Current Level: {str(current_level)}
        Next Level Index: {str(next_level_index)}
        Current Experience: {str(current_exp)}
        Rested Experience: {str(rested_exp)}
    ''')
    return (class_id, level1, current_level, next_level_index, current_exp, current_level)


'''
Decode FFXIV IPC data for opcode 0x00fe (PublicMessage). This opcode handles
chat messages in public chats. The chat message itself is always stored in byte
offset 48.

Format:
    8 byte - UniqueID
    4 byte - CharacterID
    2 byte - UserServer
    1 byte - Message Type (Shout, Yell, or Say chat channels)
    1 byte - Unknown (probably padding)
    32 byte - Nickname (Message sender's username)
    ? byte - Message
'''
def IPC_decode_PublicMessage(data):
    class Public_Message_Type(Enum):
        Shout = 11
        Yell = 30
        Say = 10
 
    data = data[:48]
    packet = unpack('<QLHBB32s', data)

    unique_id = packet[0]
    character_id = packet[1]
    user_server = packet[2]
    message_type = packet[3]
    nickname = str(binascii.b2a_hex(packet[5]))
    message = str(binascii.b2a_hex(data[48:]))

    # show public message type with descriptor if it is a known message type
    message_type_text = message_type
    if(message_type in [item.value for item in Public_Message_Type]):
        message_type_text = f'{message_type} ({Public_Message_Type(message_type).name})'

    print(f'''PublicMessage:
        Unique ID: {str(unique_id)}
        Character ID: {str(character_id)}
        User Server: {str(user_server)}
        Message Type: {message_type_text}
        Nickname: {nickname}
        Message: {message}
    ''')
    return (unique_id, character_id, user_server, message_type, nickname, message)


'''
Decode FFXIV IPC data for opcode 0x0065 (GroupMessage). This opcode handles
chat messages in group chats. The chat message itself is always stored in byte
offset 57.

Format:
    4 byte - GroupID
    2 byte - Message Type (Linkshell, Free Company, or Novice Network)
    2 byte - Server
    8 byte - UniqueID
    4 byte - CharacterID
    2 byte - UserServer (The message sender's server?)
    2 byte - UserServer2 (The message recipient's server?)
    1 byte - Unknown (probably padding)
    32 byte - Nickname (Message sender's username)
    ? byte - Message
'''
def IPC_decode_GroupMessage(data):
    class Group_Message_Type(Enum):
        Linkshell = 2
        FreeCompany = 3
        NoviceNetwork = 4
 
    data = data[:57]
    packet = unpack('<LHHQLHHB32s', data)

    group_id = packet[0]
    message_type = packet[1]
    server = packet[2]
    unique_id = packet[3]
    character_id = packet[4]
    user_server = packet[5]
    user_server2 = packet[6]
    nickname = str(binascii.b2a_hex(packet[8]))
    message = str(binascii.b2a_hex(data[57:]))

    # show group message type with descriptor if it is a known message type
    message_type_text = message_type
    if(message_type in [item.value for item in Group_Message_Type]):
        message_type_text = f'{message_type} ({Group_Message_Type(message_type).name})'

    print(f'''GroupMessage:
        Group ID: {str(group_id)}
        Message Type: {message_type_text}
        Server: {str(server)}
        Unique ID: {str(unique_id)}
        Character ID: {str(character_id)}
        User Server: {str(user_server)}
        User Server 2: {str(user_server2)}
        Nickname: {nickname}
        Message: {message}
    ''')
    return (group_id, message_type, server, unique_id, character_id, user_server, user_server2, nickname, message)


main()


