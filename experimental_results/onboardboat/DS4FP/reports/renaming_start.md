# Gafgyt/Mirai Botnet Binary Analysis - Function Renaming Summary

## Binary: arm6 (ARM 32-bit LE, ELF)

## Overview
This is a Gafgyt (Qbot) / Mirai botnet variant targeting ARM-based IoT devices. The binary is statically linked and stripped, with all function names obfuscated. The analysis renamed 100+ functions to reflect their actual behavior.

---

## Functions Renamed

### Core Bot Infrastructure

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000c3c4 | FUN_0000c3c4 | **main** | Entry point called from libc startup; handles daemonization fork, C2 connection, attack/scanner/killer init, and select-based main loop |
| 0x0000c260 | FUN_0000c260 | **single_instance_bind** | Creates a socket, binds to port 0x9dc7 (40391), ensures single instance; matches guide's "Single-Instance Port" pattern |
| 0x0000cc40 | FUN_0000cc40 | **rand_init** | Seeds PRNG with XOR of getpid(), getppid(), and clock() values |
| 0x00008a44 | FUN_00008a44 | **attack_init** | Registers DDoS attack methods with ID-to-function-pointer mappings in a table |
| 0x0000bc38 | FUN_0000bc38 | **killer_init** | Initializes a counter tracking competing malware processes to kill |
| 0x0000bc78 | FUN_0000bc78 | **killer_scan_proc** | Scans /proc filesystem, reads /proc/[pid]/cmdline and /proc/[pid]/status, kills matching rival bot processes via SIGKILL |
| 0x0000c174 | FUN_0000c174 | **scanner_init** | Initializes telnet scanner: sets up scanner paths via scanner_setup(), opens watchdog device, forks scanner processes |
| 0x0000c0f4 | FUN_0000c0f4 | **scanner_report** | Opens a file and writes scanner findings (PID info) to report back |
| 0x0000bf9c | FUN_0000bf9c | **scanner_setup** | Creates 7 directories for scanner operations via snprintf + mkdir calls, opens a status file |
| 0x0000bee4 | FUN_0000bee4 | **scanner_connect** | Connects to target IPs during scanning, reads/writes data via socket |
| 0x0000833c | FUN_0000833c | **killer_cleanup** | Iterates through 8 process slots, kills each with SIGKILL (signal 9) using both positive and negative PID kill |

### String Table (XOR-Obfuscated Strings)

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000cec0 | FUN_0000cec0 | **table_unlock_val** | XOR-decrypts obfuscated string at table[index] using a 4-byte key from DAT_0000cf5c; iterates over each byte |
| 0x0000cf60 | FUN_0000cf60 | **table_lock_val** | XOR-encrypts (re-obfuscates) string at table[index] using same 4-byte key pattern |
| 0x00008574 | FUN_00008574 | **table_retrieve_val** | Searches option array for matching ID, returns string pointer (calls strdup on match) |
| 0x000085e0 | FUN_000085e0 | **table_retrieve_int** | Searches option array for matching ID, returns integer value (calls strtol on match) |
| 0x0000ce9c | FUN_0000ce9c | **table_get_entry** | Retrieves a table entry by index (8-byte entries: pointer + length) |

### DDoS Attack Handlers

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x00008e74 | FUN_00008e74 | **attack_udp_plain** | Creates UDP sockets (socket(AF_INET, SOCK_DGRAM, 0)), sends flood of UDP packets to targets |
| 0x00009160 | FUN_00009160 | **attack_method_std** | Creates UDP sockets with IPPROTO_UDP (socket(AF_INET, SOCK_DGRAM, 17)), standard UDP flood |
| 0x0000944c | FUN_0000944c | **attack_method_raw** | Creates raw socket (socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)), crafts raw IP packets with protocol=1 (ICMP), falls back to attack_method_std |
| 0x00009844 | FUN_00009844 | **attack_gre_flood** | Creates raw socket (socket(AF_INET, SOCK_RAW, IPPROTO_TCP)), sets IP_HDRINCL, crafts IP packets with protocol=0x2f (GRE), dual IP header (tunnel), falls back to attack_method_std |
| 0x00009e74 | FUN_00009e74 | **attack_tcp_stomp** | Creates TCP sockets (socket(AF_INET, SOCK_STREAM, 0)), connects to targets and sends data; state machine with connect/send/retry |
| 0x0000a1d0 | FUN_0000a1d0 | **attack_tcp_raw** | Creates raw socket (socket(AF_INET, SOCK_RAW, IPPROTO_TCP)), crafts raw TCP packets with TCP flags (URG/ACK/PSH/RST/SYN/FIN), falls back to attack_tcp_stomp |
| 0x0000aa38 | FUN_0000aa38 | **attack_udp_custom** | Creates raw socket (socket(AF_INET, SOCK_RAW, IPPROTO_TCP)), crafts custom packets with TCP flags, generates random payload data, falls back to attack_tcp_stomp |
| 0x0000b1ec | FUN_0000b1ec | **attack_tcp_ack** | Creates raw socket (socket(AF_INET, SOCK_RAW, IPPROTO_TCP)), crafts TCP packets with configurable TCP flags (URG/ACK/PSH/RST/SYN/FIN), sets MSS/TCP options, falls back to attack_tcp_stomp |
| 0x0000b978 | FUN_0000b978 | **attack_udp_std_alt** | Creates UDP sockets with IPPROTO_UDP (socket(AF_INET, SOCK_DGRAM, 17)), alternative UDP flood variant |

### Attack Infrastructure

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x00008650 | FUN_00008650 | **attack_parse_packet** | Parses C2 attack command packets into target arrays and option structures |
| 0x000081b8 | FUN_000081b8 | **attack_build_targets** | Builds target list from parsed packet data, allocates memory for target structures |
| 0x00008190 | FUN_00008190 | **attack_dispatch** | Dispatches attack to appropriate handler function based on method ID byte |
| 0x0000d000 | FUN_0000d000 | **attack_method_names_init** | Initializes attack method name strings (allocates memory and copies hardcoded names) |

### Random Number Generators

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000cb64 | FUN_0000cb64 | **rand_next** | Classic LCG PRNG: x = x ^ (x << 11); x = x ^ (x >> 13); x = x ^ (x >> 8); matches Mirai's rand_next |
| 0x0000cbc0 | FUN_0000cbc0 | **rand_range** | Returns random number in [0, max) range using modular multiplication |
| 0x0000cdf8 | FUN_0000cdf8 | **rand_range_alt** | Alternative random range function with different LCG parameters |
| 0x0000cca8 | FUN_0000cca8 | **rand_alt** | Alternative LCG implementation with different shift constants |
| 0x0000cd1c | FUN_0000cd1c | **util_rand_buf** | Fills buffer with random bytes using the LCG generator |

### System Call Wrappers

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000d7e0 | FUN_0000d7e0 | **sys_fork** | syscall 2 (fork) |
| 0x0000d728 | FUN_0000d728 | **sys_getpid** | syscall 20 (getpid) |
| 0x0000d66c | FUN_0000d66c | **sys_getppid** | syscall 64 (getppid) |
| 0x0000dbb0 | FUN_0000dbb0 | **sys_close** | syscall 6 (close) |
| 0x0000d8f0 | FUN_0000d8f0 | **sys_kill** | syscall 37 (kill) |
| 0x0000d6b4 | FUN_0000d6b4 | **sys_open** | syscall 5 (open) |
| 0x0000daf0 | FUN_0000daf0 | **sys_ioctl** | syscall 54 (ioctl) |
| 0x0000d8bc | FUN_0000d8bc | **sys_read** | syscall 3 (read) |
| 0x0000da30 | FUN_0000da30 | **sys_write** | syscall 4 (write) |
| 0x0000d854 | FUN_0000d854 | **sys_brk** | syscall 12 (brk) |
| 0x0000d680 | FUN_0000d680 | **sys_mprotect** | syscall 10 (mprotect) |
| 0x0000d770 | FUN_0000d770 | **sys_gettimeofday** | syscall 78 (gettimeofday) |
| 0x0000d924 | FUN_0000d924 | **sys_gettimeofday2** | syscall 78 (gettimeofday variant) |
| 0x0000d814 | FUN_0000d814 | **sys_select** | syscall 142 (select) |
| 0x0000d888 | FUN_0000d888 | **sys_readlink** | syscall 85 (readlink) |
| 0x0000da64 | FUN_0000da64 | **sys_pipe** | syscall 66 (pipe) |
| 0x0000d714 | FUN_0000d714 | **sys_gettid** | syscall 199 (gettid) |
| 0x0000d73c | FUN_0000d73c | **sys_setpgid** | syscall 57 (setpgid) |
| 0x0000d7a0 | FUN_0000d7a0 | **sys_getpeername** | syscall 172 (getpeername) |
| 0x0000d958 | FUN_0000d958 | **sys_fcntl** | syscall 221/55 (fcntl) |
| 0x0000d9c4 | FUN_0000d9c4 | **sys_fcntl2** | syscall 221/55 (fcntl variant) |
| 0x0000da98 | FUN_0000da98 | **sys_stat** | syscall 106 (stat) |
| 0x0000db44 | FUN_0000db44 | **sys_sigprocmask** | syscall 175 (sigprocmask) |
| 0x0000db7c | FUN_0000db7c | **sys_uname** | syscall 83 (uname) |
| 0x00012ac4 | FUN_00012ac4 | **sys_mmap** | mmap system call |
| 0x00012da0 | FUN_00012da0 | **sys_munmap** | munmap system call |
| 0x00012e08 | FUN_00012e08 | **sys_mremap** | mremap system call |
| 0x00012e90 | FUN_00012e90 | **sys_exit** | exit system call |
| 0x00011950 | FUN_00011950 | **sys_exit_group** | exit_group system call |
| 0x00012954 | FUN_00012954 | **sys_getpagesize** | getpagesize system call |
| 0x0001297c | FUN_0001297c | **sys_sched_getaffinity** | sched_getaffinity system call |
| 0x000129b0 | FUN_000129b0 | **sys_getgid** | getgid system call |
| 0x000129c4 | FUN_000129c4 | **sys_getuid** | getuid system call |
| 0x00012b30 | FUN_00012b30 | **sys_getegid** | getegid system call |

### Socket System Call Wrappers

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000fab4 | FUN_0000fab4 | **sys_socket** | socket() syscall |
| 0x0000f8a0 | FUN_0000f8a0 | **sys_connect** | connect() syscall |
| 0x0000f8d8 | FUN_0000f8d8 | **sys_send** | send() syscall |
| 0x0000f9c0 | FUN_0000f9c0 | **sys_sendto** | sendto() syscall |
| 0x0000f9f8 | FUN_0000f9f8 | **sys_sendmsg** | sendmsg() syscall (sendmmsg variant) |
| 0x0000f868 | FUN_0000f868 | **sys_recv** | recv() syscall |
| 0x0000f948 | FUN_0000f948 | **sys_recvfrom** | recvfrom() syscall |
| 0x0000f910 | FUN_0000f910 | **sys_getsockname** | getsockname() syscall |
| 0x0000f98c | FUN_0000f98c | **sys_listen** | listen() syscall |
| 0x0000fa70 | FUN_0000fa70 | **sys_setsockopt** | setsockopt() syscall |
| 0x0000fa30 | FUN_0000fa30 | **sys_sendmsg_alt** | sendmsg() alternative (sendto with msghdr) |

### Utility Functions

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000d1e4 | FUN_0000d1e4 | **util_strlen** | Iterates through string counting non-null characters |
| 0x0000d20c | FUN_0000d20c | **util_strcpy** | Copies string from src to dst, returns length |
| 0x0000d254 | FUN_0000d254 | **util_memcpy** | Copies n bytes from src to dst |
| 0x0000d448 | FUN_0000d448 | **util_itoa** | Converts integer to ASCII string (supports negative, base 2-36) |
| 0x0000d278 | FUN_0000d278 | **util_strtol** | Converts string to long integer (supports base prefixes) |
| 0x0000d544 | FUN_0000d544 | **util_udiv** | Unsigned division with remainder |
| 0x0000d640 | FUN_0000d640 | **util_mod** | Modulo operation |
| 0x0000f3b0 | FUN_0000f3b0 | **util_memset** | Fills memory with byte value (optimized for 32-bit) |
| 0x0000f450 | FUN_0000f450 | **util_strlen** | Returns string length (word-aligned optimized) |
| 0x0000f4c0 | FUN_0000f4c0 | **util_strstr** | Finds substring in string (strstr) |
| 0x0000f5bc | FUN_0000f5bc | **util_strnlen** | Returns string length with max limit (strnlen) |
| 0x0000f840 | FUN_0000f840 | **util_strdup** | Duplicates string (strdup) |
| 0x0000f688 | FUN_0000f688 | **util_strncpy** | Copies string with length limit (strncpy wrapper) |
| 0x0000f6a0 | FUN_0000f6a0 | **util_ultoa** | Converts unsigned long to ASCII (ultoa) |
| 0x00008d80 | FUN_00008d80 | **util_checksum** | Computes 16-bit checksum (used for IP/TCP header checksums) |
| 0x00008dd0 | FUN_00008dd0 | **util_checksum2** | Computes pseudo-header checksum for TCP/UDP |
| 0x0000fcc4 | FUN_0000fcc4 | **util_fls** | Find last set bit (floor log2) |
| 0x0000dfd8 | FUN_0000dfd8 | **util_errno** | Returns address of errno variable |
| 0x0000dff4 | FUN_0000dff4 | **util_clock** | Returns clock time (CLOCK_MONOTONIC) |
| 0x0000d3b4 | FUN_0000d3b4 | **util_local_ip** | Gets local IP address via UDP socket + getsockname |
| 0x0000fd3c | FUN_0000fd3c | **util_malloc** | Memory allocation (malloc wrapper) |
| 0x0001065c | FUN_0001065c | **util_calloc** | Memory allocation with zero-init (calloc wrapper) |
| 0x00010790 | FUN_00010790 | **util_realloc** | Memory reallocation (realloc wrapper) |
| 0x00010da8 | FUN_00010da8 | **util_free** | Memory deallocation (free wrapper) |
| 0x0000ddac | FUN_0000ddac | **util_fdopen** | Opens file by path, returns file descriptor structure |
| 0x0000de58 | FUN_0000de58 | **util_fdopen2** | Alternative file open (with fcntl) |
| 0x0000def0 | FUN_0000def0 | **util_readdir** | Reads directory entries from DIR handle |
| 0x0000dbe4 | FUN_0000dbe4 | **util_fdclose** | Closes file descriptor structure |
| 0x0000dcdc | FUN_0000dcdc | **util_fdget** | Gets file info structure |
| 0x0000e028 | FUN_0000e028 | **util_snprintf** | snprintf implementation |
| 0x0000e384 | FUN_0000e384 | **util_vsnprintf** | vsnprintf implementation |
| 0x0000ea6c | FUN_0000ea6c | **util_vsnprintf_init** | vsnprintf state initialization |
| 0x0000eb0c | FUN_0000eb0c | **util_vsnprintf_setup** | vsnprintf argument setup |
| 0x0000eb50 | FUN_0000eb50 | **util_vsnprintf_parse** | vsnprintf format string parser |
| 0x0000ed54 | FUN_0000ed54 | **util_vsnprintf_format** | vsnprintf format specifier handler |
| 0x0000ed00 | FUN_0000ed00 | **util_spec_priority** | Format specifier priority lookup |
| 0x0000e2ac | FUN_0000e2ac | **util_fwrite** | File write (write to FILE*) |
| 0x0000e300 | FUN_0000e300 | **util_fwrite2** | File write with formatting |
| 0x0000f2fc | FUN_0000f2fc | **util_fwrite_impl** | fwrite implementation |
| 0x0000f2c4 | FUN_0000f2c4 | **util_fwrite_char** | fputc implementation |
| 0x0000e174 | FUN_0000e174 | **util_fwrite_init** | FILE* initialization |
| 0x0000e1a8 | FUN_0000e1a8 | **util_fwrite_flush** | FILE* flush |
| 0x0000e27c | FUN_0000e27c | **util_fwrite_avail** | FILE* available space |
| 0x0000fba0 | FUN_0000fba0 | **util_sigaction** | Signal handler setup (sigaction) |
| 0x0000fb8c | FUN_0000fb8c | **util_sigemptyset** | Initialize empty signal set |
| 0x0000fb48 | FUN_0000fb48 | **util_sigaddset** | Add signal to signal set |
| 0x0000faec | FUN_0000faec | **util_kill_neg** | Kill with negative PID (process group) |
| 0x0000fb2c | FUN_0000fb2c | **util_sleep** | Sleep for n seconds |
| 0x00011a08 | FUN_00011a08 | **util_sleep_sec** | Sleep for n seconds (nanosleep wrapper) |
| 0x000121d8 | FUN_000121d8 | **util_nanosleep** | Nanosleep implementation |
| 0x00011ab4 | FUN_00011ab4 | **util_cpu_count** | Counts CPU cores from /proc/cpuinfo or /proc/stat |
| 0x00011c00 | FUN_00011c00 | **util_sysconf** | sysconf wrapper (returns system configuration values) |
| 0x000122e8 | FUN_000122e8 | **util_setrlimit** | setrlimit wrapper |
| 0x0001233c | FUN_0001233c | **util_brk_init** | Initializes brk/heap boundaries |
| 0x0000f7a0 | FUN_0000f7a0 | **util_tcgetattr** | tcgetattr wrapper |
| 0x0000f7c4 | FUN_0000f7c4 | **util_tcgetattr_impl** | tcgetattr implementation |
| 0x0000e10c | FUN_0000e10c | **util_termios** | Terminal settings manipulation |

### Heap Management

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x00010bf4 | FUN_00010bf4 | **heap_init** | Initializes heap allocator data structures |
| 0x00010b44 | FUN_00010b44 | **heap_trim** | Trims heap (coalesces free chunks) |
| 0x00011024 | FUN_00011024 | **heap_abort** | Heap corruption abort handler |

### Other

| Address | Original Name | New Name | Evidence |
|---------|---------------|----------|----------|
| 0x0000bc34 | FUN_0000bc34 | **killer_check_timer** | Checks if it's time to run killer scan |
| 0x0000bc70 | FUN_0000bc70 | **killer_sleep** | Sleep for killer loop iteration |
| 0x00011754 | FUN_00011754 | **util_atoi** | atoi wrapper (string to int, base 10) |

---

## Key Findings

### 1. **Gafgyt/Mirai Botnet Classification**
The binary matches all structural signatures of the Gafgyt/Mirai botnet family:
- XOR-obfuscated string table with `table_init`/`table_lock_val`/`table_unlock_val` functions
- LCG PRNG matching Mirai's `rand_next` algorithm
- Multi-process forking architecture (daemonization, killer, scanner, attack)
- Raw socket DDoS attack methods with IP_HDRINCL
- Single-instance port binding

### 2. **DDoS Attack Capabilities**
The bot implements 9 distinct DDoS attack methods:
- **UDP Floods**: 3 variants (plain UDP, standard UDP, alternative UDP)
- **TCP Floods**: 3 variants (TCP stomp/connect, raw TCP, TCP ACK)
- **Raw Protocol Floods**: GRE tunnel flood, ICMP flood, custom packet flood

### 3. **Self-Preservation Mechanisms**
- **Killer Process**: Scans /proc to identify and kill competing malware instances
- **Single Instance**: Binds to a local port to prevent multiple instances
- **Process Hiding**: Uses mprotect and process renaming

### 4. **Network Architecture**
- C2 communication via TCP with select()-based event loop
- Heartbeat mechanism (sends 2-byte pings every ~60 seconds)
- Telnet brute-force scanner for lateral propagation

---

## Analysis Gaps

1. **Exact C2 protocol details**: The exact packet format for C2 commands was not fully reverse-engineered. The attack dispatch at 0x8190 parses method IDs from received packets.

2. **Scanner credentials table**: The exact credentials used for Telnet brute-forcing were not identified in this analysis.

3. **String table contents**: The XOR-encrypted strings in the table were not decrypted; only the encryption/decryption mechanism was identified.

4. **Some attack method IDs**: The exact mapping of function addresses to attack method IDs (0x00-0x10) could not be fully confirmed without resolving the function pointer table at 0x8d50.

5. **Several small helper functions**: A few remaining FUN_* functions at addresses below 0x10000 were not renamed as their purpose could not be confidently determined without deeper analysis.
