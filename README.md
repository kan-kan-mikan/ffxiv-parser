# A Final Fantasy XIV Patch 5.58 global server packet sniffer and parser

A very basic Python packet sniffer that decodes basic FFXIV packet header, segment header, and IPC header structure along with parsing a few in-game actions into something more human readable. All information in this parser was reverse engineered by the community and is subject to change in any future game update.

## How It Works
FFXIV packets are delivered over TCP. Multiple FFXIV packets can be attached to a single TCP payload (though this parser only reads from the first FFXIV packet within a TCP packet). Each FFXIV packet is composed of three parts: the packet header, segment header, and an optional IPC header. The IPC header is included if the segment type included in the segment header is 3. All IPC data appended to the IPC header is the actual game data we want to decode. Each bit of IPC data also has an associated IPC opcode that tells the game how it should be decoded.

### FFXIV Packet Header
* 16 byte - Magic number ('5252a041ff5d46e27f2a644d7b99c475' in hex, supposedly decodes to FF14ARR)
* 8 byte - Timestamp in UNIX time
* 2 byte - Packet size
* 2 byte - Unknown (always seems to be all 0's, might be padding)
* 2 byte - Connection type (only relevant for chat message packets)
* 2 byte - Message count
* 1 byte - Encoding
* 1 byte - Compression flag
* 2 byte - Unknown (always seems to be all 0's, might be padding)
* 2 byte - Unknown (always seems to be all 0's, might be padding)
* 2 byte - Unknown (always seems to be all 0's, might be padding)

### FFXIV Segment Header
* 4 byte - Segment size (size of the packet minus the packet header)
* 4 byte - Source (gameplay related data)
* 4 byte - Target (gameplay related data)
* 2 byte - Segment type (all gameplay related ones are type 3 for IPC)
* 2 byte - Unknown (always seems to be all 0's, might be padding)

### FFXIV Segment Types
* SESSION_INIT = 1
* IPC = 3
* CLIENT_KEEPALIVE = 7
* SERVER_KEEPALIVE = 8
* ENCRYPTION_INIT = 9

### FFXIV IPC Header
* 2 byte - Magic number
* 2 byte - IPC opcode (identifies what the IPC data is for)
* 2 byte - Unknown (always seems to be all 0's, might be padding)
* 2 byte - Server ID
* 4 byte - Timestamp in UNIX time
* 4 byte - Unknown (always seems to be all 0's, might be padding)

### IPC Formats

#### UpdateHpMpTp (0x01a7)
Decode FFXIV IPC data for opcode 0x01a7 (UpdateHpMpTp). This opcode handles updating player health, mana, and tactical point regeneration. Tactical points have not been used in the game since Patch 5.0.

**Format:**
* 4 byte - HP
* 2 byte - MP
* 2 byte - TP (random data that isn't used anymore)

#### UpdateClassInfo (0x03bf)
Decode FFXIV IPC data for opcode 0x03bf (UpdateClassInfo). This opcode handles the character's currently equipped class, level, and experience points. This opcode was reverse engineered by myself, and I'm not actually certain this is entirely correct. The format itself wasn't reverse engineered by me, and I'm not certain this is correct either.

**Format:**
* 1 byte - ClassID (this list isn't reverse engineered)
* 1 byte - Level1
* 2 byte - Current level
* 4 byte - Next level index
* 4 byte - Current experience
* 4 byte - Rested experience (amount of bonus experience that can be gained currently)

#### PublicMessage (0x00fe)
Decode FFXIV IPC data for opcode 0x00fe (PublicMessage). This opcode handles chat messages in public chats. The chat message itself is always stored in byte offset 48.

**Format:**
* 8 byte - UniqueID
* 4 byte - CharacterID
* 2 byte - UserServer
* 1 byte - Message Type (Shout, Yell, or Say chat channels)
* 1 byte - Unknown (probably padding)
* 32 byte - Nickname (Message sender's username)
* ? byte - Message

#### GroupMessage (0x0065)
Decode FFXIV IPC data for opcode 0x0065 (GroupMessage). This opcode handles chat messages in group chats. The chat message itself is always stored in byte offset 57.

**Format:**
* 4 byte - GroupID
* 2 byte - Message Type (Linkshell, Free Company, or Novice Network)
* 2 byte - Server
* 8 byte - UniqueID
* 4 byte - CharacterID
* 2 byte - UserServer (The message sender's server?)
* 2 byte - UserServer2 (The message recipient's server?)
* 1 byte - Unknown (probably padding)
* 32 byte - Nickname (Message sender's username)
* ? byte - Message

## Important References
* https://github.com/zhyupe/FFXIV-Packet-Dissector (Wireshark plugin with many IPCs reverse engineered, though for the Chinese server's opcodes)
* https://github.com/ravahn/machina (Includes some opcodes for the global server)
* https://xiv.dev/network/packet-structure (Described FFXIV packet structure and format)
