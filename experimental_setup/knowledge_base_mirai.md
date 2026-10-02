# Gafgyt/Mirai Botnet Pattern Recognition & Classification Guide

This guide is designed to help AI agents identify and classify stripped or obfuscated malware samples belonging to the **Gafgyt (Qbot) / Mirai** botnet family. By examining structural control-flow patterns and function signatures, an agent can verify if a target binary matches this family.

---

## 1. Quick Classification Cheat Sheet (MD-Only Detection)

To quickly identify if a stripped binary belongs to this family without decompilation, look for the following characteristics:

| Feature / Signatures | Value / Structural Signature |
| :--- | :--- |
| **Typical Target Port** | Connecting to C2 on port **53537** (`0xd121`) or **48101** (`0xbbad`). |
| **Single-Instance Port** | Binding to port **8345** (`0x2099`) or **48101** to lock the system. |
| **Startup Signature** | Writes an unencrypted banner/signature from `table_retrieve_val(1)` to `stdout` (FD 1) right before daemonization. |
| **C2 Password parameter** | Accepts a password as its first argument `argv[1]`, which is sent to C2 on initial connect. |
| **Process Renaming** | Rewriting `argv[0]` and calling `prctl(PR_SET_NAME, "/var/Sofia")` or `/var/run/` variants. |
| **String Obfuscation** | Presence of a string table decryptor (`table_init` / `table_unlock_val` / `table_lock_val`) utilizing custom XOR loops. |
| **Network Engine** | Loop utilizing `select` to handle C2 connection states, heartbeat pings (`\x00\x00` every 60s), and scanner connections. |

---

## 2. Forking Architecture and Process Model

This family utilizes a distinct multi-forked process topology to manage background tasks, ensure resilience, and implement timers for DDoS attacks.

```
          [main] (Initial Process)
             │
             ├── Writes banner (Signature) to stdout
             │
             ├── fork() ── [Parent] Exits
             │
             [main daemon] (Session Leader, runs C2 select loop)
                │
                ├── fork() ──── [killer_init] (Kills competing malware instances)
                │
                ├── fork() ──── [scanner_init] (Telnet raw SYN / Brute-forcer)
                │
                └── fork() ──── [attack_start] (DDoS Supervisor)
                                   │
                                   └── fork() ── [attack_timer] (Grandchild)
                                                    │
                                                    ├── sleep(duration)
                                                    └── kill(supervisor_pid, 9)
```

### A. Daemonization Fork (`main`)
- **Location**: Inside `main` before C2 connect.
- **Pattern**:
  ```c
  pid_daemon = fork();
  if (pid_daemon > 0) {
      return 0; // Parent exits, leaving daemon running in background
  }
  setsid(); // Detaches from terminal, creates new process group
  close(0); close(1); close(2); // Closes stdin/stdout/stderr
  ```
- **Cleanup**: In the main loop, if the single-instance controller socket (`fd_ctrl`) becomes readable, the bot executes `kill(-session_id, 9)` which terminates the entire daemon process group.

### B. Module Initialization Forks (`killer_init` & `scanner_init`)
- **Killer Process**: Spawns a background process that loops infinitely (sleeping 10s), scanning `/proc` to kill rival botnet instances on the device.
- **Scanner Process**: Spawns a background process that drives raw SYN packet generations and runs the Telnet brute-force state machine.

### C. Double-Fork Attack Execution (`attack_start`)
- **Location**: Spawns attacks received from C2.
- **Pattern**:
  ```c
  supervisor_pid = fork();
  if (supervisor_pid > 0 || supervisor_pid == -1) {
      return; // Parent daemon returns to C2 loop to receive further commands
  }
  // Inside the Attack Supervisor Process:
  timer_pid = fork();
  if (timer_pid == 0) {
      // Grandchild Timer Process:
      sleep(duration); // Wait for attack period to expire
      kill(getppid(), 9); // Kill supervisor process (terminating attack flood)
      exit(0);
  }
  // Supervisor Process:
  (*methods[method_idx]->pFunc)(...); // Enters infinite DDoS flooding loop
  ```

---

## 3. Structural Control Flow of the `main` Function

The Entrypoint `main` control flow sequence:

```mermaid
graph TD
    A[Start] --> B[Initialize Signals<br>Mask SIGINT/SIGTERM, Ignore SIGCHLD]
    B --> C[Watchdog Handling<br>Open /dev/watchdog & ioctl]
    C --> D[Environment Setup<br>chdir / & get local IP]
    D --> E[Config & Single-Instance<br>table_init & bind local port 8345]
    E --> F[Password Extraction & Process Hiding<br>Extract argv[1] C2 password, Rewrite argv, & prctl PR_SET_NAME]
    F --> G[Banner Output<br>Retrieve & write banner to stdout]
    G --> H[Daemonize<br>fork parent exits & close std FDs]
    H --> I[Sub-Module Init<br>attack_init, killer_init, huawei_init, scanner_init]
    I --> J[Select-Based Main Loop]
    J --> K{Server FD == -1?}
    K -- Yes --> L[Create non-blocking Socket & Connect to C2]
    K -- No --> M[Add FDs to fd_set]
    L --> M
    M --> N[select timeout 10s]
    N --> O{select return value?}
    O -- 0 Timeout --> P[Increment heartbeats<br>If % 6 == 0, send 2-byte ping]
    O -- fd_ctrl readable --> Q[Incoming local client<br>Kill killer/attacks/children & exit]
    O -- fd_serv readable/writable --> R[Process packet data / connection success]
```

### Signature Heuristics in Assembly/Decompilation:
1. **Startup Banner/Signature**:
   ```c
   banner = (char *)table_retrieve_val(1, &banner_len);
   write(1, banner, banner_len);
   write(1, "\n", 1);
   table_lock_val(1);
   ```
2. **Password Extraction**:
   ```c
   if ((argc == 2) && (len = strlen(argv[1]), len < 0x20)) {
       strcpy(c2_password, argv[1]);
       memset(argv[1], 0, len);
   }
   ```
3. **C2 Port Check & Authentication**:
   ```c
   srv_addr.sa_family = 2; // AF_INET
   srv_addr.sa_data[0] = 0xd1; // Port 53537 (0xd121)
   srv_addr.sa_data[1] = 0x21;
   ```

---

## 4. Attack Method Identification

The C2 commands carry a **Method ID** byte at offset 4 of the packet. The `attack_init` function associates these IDs with attack handler function pointers. Use the table below to map stripped attack routines:

| ID (Hex) | Attack Function | DDoS Technique | Description / Pattern |
| :--- | :--- | :--- | :--- |
| `0x00` | `attack_tcp_stomp` | TCP Stomp | Sends customized TCP packets after establishing a TCP connection. |
| `0x01` | `attack_udp_plain` | UDP Plain Flood | Floods target with raw, high-speed UDP packets. |
| `0x02` | `attack_method_std` | Standard UDP Flood | Loops UDP socket creations, binding random local source ports. |
| `0x03` | `attack_method_tcp` | TCP Generic Flood | Floods TCP connection requests with options parsed from C2. |
| `0x04` | `attack_tcp_ack` | TCP ACK Flood | Sends raw TCP packets with the ACK flag set to saturate network state tables. |
| `0x05` | `attack_tcp_syn` | TCP SYN Flood | Sends raw TCP packets with the SYN flag set (half-open connection flood). |
| `0x06` | `attack_method_hexflood` | Hex Payload Flood | UDP flood sending raw hexadecimal strings defined by options. |
| `0x07` | `attack_method_stdhex` | Standard Hex Flood | Combines standard UDP sockets with hexadecimal payloads. |
| `0x08` | `attack_method_nudp` | NUDP Flood | Non-conforming UDP packets designed to bypass generic firewalls. |
| `0x09` | `attack_method_udphex` | UDP Hex Flood | Fast UDP flood utilizing custom hex payloads. |
| `0x0a` | `attack_method_tcpxmas` | TCP Xmas Flood | Sends TCP packets with FIN, URG, and PSH flags enabled (Xmas tree). |
| `0x0b` | `attack_tcp_bypass` | TCP Bypass Flood | Formulates specific TCP headers to bypass standard stateful mitigation. |
| `0x0c` | `attack_method_raw` | Raw IP Socket Flood | Utilizes `IPPROTO_RAW` sockets to forge raw IP headers. |
| `0x0d` | `attack_udp_custom` | Custom UDP Flood | UDP flood utilizing specialized custom string buffers. |
| `0x0e` | `attack_method_ovhdrop` | OVH Drop Flood | Tailored UDP payloads targetting weaknesses in OVH anti-DDoS filters. |
| `0x0f` | `attack_method_nfo` | NFO Flood | Bypasses NFO (Nuclear Fall Out) game server mitigations. |
| `0x10` | `attack_method_ovh` | OVH Bypass Flood | Designed specifically to bypass OVH DDoS mitigation profiles. |

---

## 5. Key Data Structure Fingerprints

### A. Target Array Entry (`struct target`)
- **Size**: `24 bytes` (passed in EAX/EDX or on the stack).
- **Structure**:
  ```c
  struct target {
      sockaddr addr;       // 16 bytes (contains target IP at offset 4)
      uint32_t netmask;    // 4 bytes (offset 16)
      char cidr;           // 1 byte (offset 20)
  };
  ```

### B. Option Array Entry (`struct option`)
- **Size**: `8 bytes`.
- **Structure**:
  ```c
  struct option {
      char *val;           // 4 bytes (offset 0) - Pointer to option string
      char id;             // 1 byte (offset 4) - Option flag ID
  };
  ```

### C. Active Scanner Connection (`struct scanner_conn`)
- **Size**: `288 bytes` (allocated inside `conn_table` inside child scanner).
- **Structure**:
  ```c
  struct scanner_conn {
      int auth_index;       // offset 0 (4 bytes) - Credentials array index
      int fd;               // offset 4 (4 bytes) - Socket descriptor
      int last_activity;    // offset 8 (4 bytes) - Last packet activity timestamp
      int state;            // offset 12 (4 bytes) - Current state (Telnet/SSH nego)
      uint32_t ip;          // offset 16 (4 bytes) - Target IP
      uint16_t port;        // offset 20 (2 bytes) - Target Port
      int buf_len;          // offset 24 (4 bytes) - Bytes count in buffer
      char buf[256];        // offset 28 (256 bytes) - Read buffer
      char retry_count;     // offset 284 (1 byte) - Retry counter
  };
  ```
