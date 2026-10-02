# Gafgyt/Qbot Botnet Binary Analysis - Renaming Summary

## Binary: 021e1c202a1d8defd3752ab749e50dac53645e40fa09d50aea9fa8004f48ba27.elf
## Architecture: x86-64 ELF, Statically Linked

---

## Functions Renamed (12 total)

### Utility Functions (Botnet-specific)

| Function | Address | Evidence |
|----------|---------|----------|
| `rand_range` | 0x0040dc40 | Uses same PRNG state (`DAT_0051c9e0`-`DAT_0051c9ec`) as `rand_next`. Returns `min + 1 + state % (max - min)`, generating a random integer in range [min, max). Called from `attack_udp_nudp`. |
| `rand_alnum_str` | 0x0040dca0 | Generates random alphanumeric strings from charset "0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789" using the same PRNG. Used for generating random payload strings in attacks. Called from `attack_udp_std1e`. |
| `util_memsearch` | 0x0040fe70 | Searches for a byte pattern (`param_3`, length `param_4`) within a buffer (`param_1`, length `param_2`). Returns offset or -1. Standard Mirai/Gafgyt utility (equivalent to memmem/strstr). Called from `attack_gre_ip`. |
| `util_stristr` | 0x00410090 | Case-insensitive substring search. Converts both characters to lowercase (`bVar3 \| 0x60`) before comparing. Returns position or -1. Called from `attack_gre_ip` and `attack_udp_std1e`. |
| `util_strcmp` | 0x00410120 | String equality comparison. Calculates lengths of both strings, then compares character-by-character. Returns 1 if equal, 0 if not. Called from `attack_gre_ip`. |
| `util_strncmp` | 0x00410190 | String comparison with explicit length limit. Compares first `param_3` characters of two strings. Returns 1 if equal within limit, 0 if not. |
| `util_itoa` | 0x00410210 | Integer to ASCII string conversion. Handles base (param_2), sign, and writes to output buffer (param_3). Called from `attack_gre_ip`. |

### Syscall Wrappers (Corrected)

| Function | Address | Syscall | Evidence |
|----------|---------|---------|----------|
| `sys_read` | 0x00410554 | 0 (read) | Disassembly shows `XOR EAX,EAX` then `SYSCALL`. Only passes RDI (fd). Called from `attack_udp_std1e`. |
| `sys_wait4` | 0x00410660 | 61 (wait4) | Disassembly shows `MOV EAX,0x3d` (61 decimal) then `SYSCALL`. Passes 4 args (pid, wstatus, options, rusage). Called from `sys_waitpid` (wrapper) and `system`. |

### Misnamed Syscall Wrappers (Corrected)

| Old Name | New Name | Address | Syscall | Evidence |
|----------|----------|---------|---------|----------|
| `sys_socket2` | `sys_open` | 0x004104dc | 2 (open) | Disassembly shows `MOV EAX,0x2` then `SYSCALL`. **Confirmed**: `opendir()` calls this function with directory path and flags `0x10800` (O_RDONLY \| O_DIRECTORY \| O_CLOEXEC). The function checks for O_CREAT flag (0x40) to handle the mode argument. |
| `sys_setsockopt2` | `sys_ioctl` | 0x00410448 | 16 (ioctl) | Disassembly shows `MOV EAX,0x10` (16 decimal) then `SYSCALL`. Called from `watchdog_init` with WDIOC_SETOPTIONS (0x80045704) and WDIOC_KEEPALIVE (0x80045705) ioctl commands. |

### Misnamed Botnet Function (Corrected)

| Old Name | New Name | Address | Evidence |
|----------|----------|---------|----------|
| `scanner_init` | `watchdog_init` | 0x0040ced0 | Opens watchdog device files (table entries 0x23-0x2b) via `sys_open`. Calls `sys_ioctl` with **WDIOC_SETOPTIONS** (0x80045704, type 'W' nr 4) to disable the watchdog, then loops calling **WDIOC_KEEPALIVE** (0x80045705, type 'W' nr 5) to prevent system reboot. This is a **watchdog killer**, not a scanner. |

---

## Variables Renamed (22 total)

### main() - Parameters

| Old Name | New Name | Justification |
|----------|----------|---------------|
| `param_1` | `argc` | Standard C main argument count. Checked against 2 for password validation. |
| `param_2` | `argv` | Standard C main argument vector. `argv[1]` extracted as C2 password. |

### main() - Local Variables

| Old Name | New Name | Justification |
|----------|----------|---------------|
| `local_98` | `c2_password_buf` | 32-byte buffer (`util_memset(buf, 0x20)`). Receives `strcpy` of `argv[1]` (C2 password), sent to C2 on connect. |
| `local_3a` | `pkt_len_buf` | 2-byte buffer used for network length-prefixed protocol. Receives 2-byte big-endian length values from `sys_recv`. Used for heartbeat ping (`\x00\x00`) and packet framing. |
| `local_618` | `recv_buf` | 1024-byte buffer receiving C2 command packets. Size validated against 0x400 (1024) max. Passed to `attack_parse`. |
| `local_218` | `read_fds` | fd_set for `sys_select` read monitoring. Contains `fd_ctrl` (0x51c470) and `fd_serv` (0x51c474). |
| `local_118` | `write_fds` | fd_set for `sys_select` write monitoring. Used to detect when C2 socket becomes writable (connection established). |
| `local_78` | `bind_addr` | `sockaddr_in` structure for single-instance bind. Family=2 (AF_INET), port=0x4500. |
| `local_74` | `bind_ip` | IP address for bind socket. Set to 0x100007f (127.0.0.1) or `local_ip` depending on `single_instance` flag. |
| `local_76` | `bind_port` | Port for bind socket (0x4500 = 17664). |
| `local_44` | `optval` | Reused variable: SO_REUSEADDR=1 for bind socket, getsockopt length=4 for SO_ERROR check, getsockname length=0x10. |
| `local_40` | `sock_error` | Receives SO_ERROR via `sys_getsockopt` to detect C2 connection failures. |
| `local_61c` | `session_id` | Stores `sys_setsid()` return value. Used with `sys_kill(-session_id, 9)` to terminate entire process group when single-instance socket triggers. |
| `local_198` | `signal_set` | Signal set for `sigemptyset`/`sigaddset`/`sys_sigprocmask`. Masks SIGINT (2). |
| `local_68` | `select_timeout` | Timeout structure for `sys_select`. `tv_sec=10` (10-second select timeout). |
| `local_58` | `send_timeout_sec` | Send timeout seconds for `sys_setsockopt` SO_SNDTIMEO (level=1, optname=0x14=20). Value=10. |
| `local_50` | `send_timeout_usec` | Send timeout microseconds. Value=0. |

### killer_loop() - Local Variables

| Old Name | New Name | Justification |
|----------|----------|---------------|
| `lVar3` | `proc_dir` | DIR* handle from `opendir("/proc")`. Iterated with `readdir`. |
| `auStack_428` | `status_path` | Buffer for `/proc/%s/status` path construction via `snprintf`. |
| `local_228` | `proc_name` | Buffer for process name read from `/proc/*/status`. Compared against known malware paths. |
| `local_128` | `status_line` | Line buffer for `fgets` reading status file. Checked for "Name:" prefix. |

---

## Analysis Gaps

### Functions Not Confidently Identified (Likely Statically Linked libc)

The following FUN_* functions appear to be statically linked libc functions rather than botnet-specific code. They were NOT renamed because:
- They are not part of the botnet's custom logic
- Renaming them would not improve malware understanding
- They would require extensive analysis to match specific libc implementations

Key examples:
- `FUN_00414300` - Thin wrapper calling strtol with base=10 (likely `atoi`)
- `FUN_00414320` - Full strtol implementation with base detection (0x, 0) and overflow checking
- `FUN_004144e8` - execve variant with argv construction
- `FUN_004147b4` - sysconf implementation (switch on _SC_* constants)
- `FUN_00414992` - dup2/fcntl related (checks fd, opens /dev/null)
- `FUN_004149c7` - Likely `__libc_init` or similar
- `FUN_00410a5c` through `FUN_00410f34` - Internal libc functions
- `FUN_00411570` through `FUN_00417780` - Internal libc functions (printf, stdio, etc.)

### Global Variables Not Renamed

The following global variables could benefit from renaming but were left as-is because:
- The rename_data/rename_global tools would need precise type information
- Their usage is consistent with the function renames already performed

Key globals identified:
- `DAT_0051c470` → `fd_ctrl` (single-instance bind socket)
- `DAT_0051c474` → `fd_serv` (C2 server socket)
- `DAT_0051c478` → `reconnect_delay` (backoff timer for reconnection)
- `DAT_0051c488` → `single_instance` (flag: bind succeeded)
- `DAT_0051c9bc` → `connected` (connection state flag)
- `DAT_0051c9b4` → `heartbeat_counter` (incremented each select loop iteration)
- `DAT_0051c9b0` → `watchdog_pid` (child PID from watchdog_init fork)
- `DAT_0051c9a0` → `attack_pid` (attack supervisor PID)
- `DAT_0051c9c0` → `c2_password` (global copy of C2 password)
- `DAT_0051c48c` → `table_key` (XOR key for string table)
- `DAT_0051ea80` → `local_ip` (local IP address)
- `DAT_0051eaa0` → `c2_addr` (C2 sockaddr_in structure)
- `DAT_0051ea90` → `killer_pid` (child PID from killer_init fork)
- `DAT_0051c9b8` → `watchdog_retry` (retry counter in watchdog_init)
- `DAT_0051c990` → `attack_count` (number of registered attack methods)
- `DAT_0051c998` → `attack_table` (attack method function pointer table)

---

## Key Findings

### 1. Binary Classification: Gafgyt/Qbot Variant (Mirai-derived)

The binary exhibits all structural signatures of the Gafgyt family:
- **String obfuscation**: XOR-encrypted string table with `table_init`/`table_unlock_val`/`table_lock_val`
- **Single-instance bind**: Binds to local port to prevent multiple instances
- **C2 protocol**: Length-prefixed packets, password-based authentication, 2-byte heartbeat pings
- **Attack methods**: 30+ DDoS attack methods registered in `attack_init`
- **Process forking**: Daemonization fork, killer process, watchdog process, double-fork attack execution

### 2. Corrected Misidentifications (Critical)

Three functions were previously misnamed in ways that would mislead analysis:

- **`sys_socket2` → `sys_open`**: This is the `open` syscall (EAX=2), confirmed by `opendir()` calling it with directory paths. The original name suggested socket creation, which is incorrect.

- **`sys_setsockopt2` → `sys_ioctl`**: This is the `ioctl` syscall (EAX=16), confirmed by the ioctl command codes used (WDIOC_SETOPTIONS=0x80045704, WDIOC_KEEPALIVE=0x80045705). The original name suggested socket option manipulation, which is incorrect.

- **`scanner_init` → `watchdog_init`**: This function opens watchdog device files and issues WDIOC ioctl commands to disable the hardware watchdog timer. It is NOT a scanner. The actual Telnet brute-force scanner is not present in this binary variant.

### 3. Defense Evasion Mechanisms

The binary implements two layers of defense evasion:
- **Watchdog killer** (`watchdog_init`): Opens watchdog device files and sends WDIOC_KEEPALIVE ioctls to prevent system reboot when the botnet causes instability
- **Process killer** (`killer_loop`): Scans `/proc/*/status` for known malware process names (e.g., `/bin/busybox`, `/bin/systemd`, `/tmp/condi`, `/tmp/zxcr9999`, `/var/condibot`) and kills them with SIGKILL
- **Tool disabler** (`util_disable_tools`): Calls `chmod(path, 0)` on 40 system binaries (reboot, shutdown, poweroff, halt, etc.) to prevent system administration

### 4. Attack Capabilities

30+ DDoS attack methods registered via `attack_init`, including:
- TCP: SYN, ACK, STOMP, XMAS, generic, bypass, connection flood
- UDP: Plain, standard, custom, DNS amplification, NFO, OVH bypass
- GRE/IP: GRE IP flood, raw IP flood
- Specialized: hex payload, NUDP, OVH drop

### 5. C2 Communication Protocol

- Connects to C2 on port decoded from table entry 2
- Authenticates with password from `argv[1]`
- Uses length-prefixed packet format (2-byte big-endian length + payload)
- Heartbeat ping (`\x00\x00`) sent every ~60 seconds (every 6th select timeout)
- Reconnection backoff: starts at 60s, doubles on each failure, capped
