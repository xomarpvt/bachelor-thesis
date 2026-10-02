# Gafgyt/Mirai Botnet Binary Analysis Summary

## Binary: deepsorrow
**Format**: ELF 32-bit x86, statically linked
**Image Base**: 0x08048000

---

## Functions Renamed

### String Table (XOR Obfuscation)

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08053fc6 | FUN_08053fc6 | `table_xor_decode` | XOR-decodes/encodes string table entries using a 4-byte key from `DAT_08064438`. Called in pairs to decrypt/encrypt obfuscated strings. |
| 0x08053fa0 | FUN_08053fa0 | `table_retrieve_val` | Retrieves a string pointer and length from the string table by index. Used to access obfuscated strings after unlocking. |
| 0x08054024 | FUN_08054024 | `table_lock_val` | Wrapper that calls `table_xor_decode` to re-encrypt (lock) a table entry. |
| 0x0805402e | FUN_0805402e | `table_unlock_val` | Wrapper that calls `table_xor_decode` to decrypt (unlock) a table entry. |

### Random Number Utilities

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08053f3f | FUN_08053f3f | `util_rand_range` | Generates a random number in the range [param1, param2). Uses `util_rand_next()` modulo arithmetic. |
| 0x0805a727 | FUN_0805a727 | `util_rand_generator` | Random number generator state machine. Uses LCG algorithm (`* 0x41c64e6d + 0x3039`). |

### Attack Methods

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x080494da | FUN_080494da | `attack_tcp_stomp` | Creates TCP connection (SOCK_STREAM), then sends raw TCP packets (SOCK_RAW, IPPROTO_TCP). Builds custom IP/TCP headers with configurable flags. |
| 0x08049b93 | FUN_08049b93 | `attack_tcp_syn` | Uses raw socket (SOCK_RAW, IPPROTO_TCP). Builds IP/TCP packets with SYN flag (0x02) set. Sends via `sys_sendto`. |
| 0x0804a124 | FUN_0804a124 | `attack_tcp_ack` | Uses raw socket (SOCK_RAW, IPPROTO_TCP). Builds IP/TCP packets with ACK flag (0x10) and SYN+ACK (0x50). |
| 0x0804a6e8 | FUN_0804a6e8 | `attack_method_tcp` | Uses raw socket (SOCK_RAW, IPPROTO_TCP). Generic TCP flood with configurable flags (0x50 = SYN+ACK). |
| 0x0804aba9 | FUN_0804aba9 | `attack_udp_plain` | Uses UDP sockets (SOCK_DGRAM). Connects to target, sends random payload data in a loop. |
| 0x0804aedd | FUN_0804aedd | `attack_method_nudp` | Uses UDP sockets (SOCK_DGRAM). Similar to plain UDP but uses non-conforming packet sizes. |
| 0x0804b1f9 | FUN_0804b1f9 | `attack_method_stdhex` | Uses UDP sockets (SOCK_DGRAM, IPPROTO_UDP). Connects, binds local port, sends random payload. |
| 0x0804b3e1 | FUN_0804b3e1 | `attack_method_udphex` | Uses UDP sockets (SOCK_DGRAM, IPPROTO_UDP). Similar to stdhex with different payload handling. |
| 0x0804b5f4 | FUN_0804b5f4 | `attack_method_raw` | Uses raw socket (SOCK_RAW, IPPROTO_UDP). Builds raw IP/UDP packets from scratch. |
| 0x0804b934 | FUN_0804b934 | `attack_udp_custom` | Uses raw socket (SOCK_RAW, IPPROTO_UDP). Builds IP/UDP packets with payload from string table (table index 3). |
| 0x0804bc5a | FUN_0804bc5a | `attack_tcp_bypass` | Uses raw socket (SOCK_RAW, IPPROTO_TCP). Implements IP-in-IP tunneling with inner TCP packet. |
| 0x0804c0c2 | FUN_0804c0c2 | `attack_method_ovh` | Uses raw socket (SOCK_RAW, IPPROTO_TCP). IP-in-IP tunneling similar to bypass, designed for OVH mitigation bypass. |
| 0x0804c49b | FUN_0804c49b | `attack_method_nfo` | Uses UDP sockets (SOCK_DGRAM). Connects and sends random payload. NFO game server targeted. |
| 0x0805016c | FUN_0805016c | `attack_method_ovhdrop` | Uses raw socket (SOCK_RAW, IPPROTO_UDP). Generates random application-layer protocol packets (OpenVPN, SA-MP, NTP, STUN, etc.) via function pointer table. |

### Application-Layer Protocol Builders

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08050043 | FUN_08050043 | `util_build_openvpn_packet` | Builds OpenVPN authentication/control packet structure with random session IDs. |
| 0x08050103 | FUN_08050103 | `util_build_samp_packet` | Builds SA-MP (San Andreas Multiplayer) game server query packet. Writes "SAMP" magic bytes (0x53,0x41,0x4d,0x50). |
| 0x080504bf | FUN_080504bf | `util_build_ntp_packet` | Builds NTP (Network Time Protocol) packet with timestamp from `sys_time()`. |
| 0x08050545 | FUN_08050545 | `util_build_random_http` | Randomly selects one of 3 HTTP request strings and copies to buffer. |
| 0x080505a8 | FUN_080505a8 | `util_build_stun_packet` | Builds STUN/TURN protocol packet. Writes "STNIT1..." magic (0x49335354 = "S3TI", 0x3154494e = "1TIN"). |
| 0x08050611 | FUN_08050611 | `util_build_random_dns` | Randomly selects one of 3 DNS-like query packets. |
| 0x08050674 | FUN_08050674 | `util_build_gre_packet` | Builds GRE (Generic Routing Encapsulation) protocol packet. |
| 0x080506e1 | FUN_080506e1 | `util_build_memcache_packet` | Builds Memcached protocol query packet for amplification attack. |
| 0x08050be0 | FUN_08050be0 | `util_build_ldap_packet` | Builds LDAP (Lightweight Directory Access Protocol) query packet. |
| 0x080511ef | FUN_080511ef | `util_build_portmap_packet` | Builds Portmap/RPCbind query packet for amplification. |
| 0x08051226 | FUN_08051226 | `util_build_ntp_monlist` | Builds NTP monlist request packet for amplification attack. |
| 0x08051ab8 | FUN_08051ab8 | `util_build_snmp_packet` | Builds SNMP (Simple Network Management Protocol) query packet. |
| 0x08051ae8 | FUN_08051ae8 | `util_build_tftp_packet` | Builds TFTP (Trivial File Transfer Protocol) read request packet. |
| 0x080520f3 | FUN_080520f3 | `util_build_ssdp_packet` | Builds SSDP (Simple Service Discovery Protocol) M-SEARCH packet for amplification. |
| 0x08052138 | FUN_08052138 | `util_build_ard_packet` | Builds Apple Remote Desktop (ARD) protocol packet. |

### DNS Resolution Functions

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08053a4c | FUN_08053a4c | `dns_parse_name` | Parses DNS name encoding (handles compression pointers 0xc0+). Used in DNS response parsing. |
| 0x08053a90 | FUN_08053a90 | `dns_response_free` | Frees DNS response structure (frees IP list and struct). |
| 0x08053abf | FUN_08053abf | `dns_domain_encode` | Encodes domain name into DNS query format (length-prefixed labels). |
| 0x08053b0b | FUN_08053b0b | `dns_resolve` | Performs DNS resolution by sending query to DNS server, parsing response, extracting A records. |

### String/Character Utilities

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08053784 | FUN_08053784 | `util_strcat` | Custom strcat: finds end of dest string, then copies source string. |
| 0x08053847 | FUN_08053847 | `util_is_alpha` | Checks if character is alphabetic (a-z, A-Z) using range checks. |
| 0x0805387d | FUN_0805387d | `util_is_digit` | Checks if character is a digit (0-9): `(byte)(param_1 - 0x30U) < 10`. |
| 0x08053862 | FUN_08053862 | `util_is_space` | Checks if character is whitespace. Used in `util_strtol` for skipping whitespace. |
| 0x08053905 | FUN_08053905 | `util_strcmp_eq` | String equality comparison. Returns 1 if equal, 0 if not. |
| 0x08058f13 | FUN_08058f13 | `util_strcmp` | String comparison returning -1/0/1 (standard strcmp semantics). |
| 0x08058f9d | FUN_08058f9d | `util_strstr` | Substring search (strstr equivalent). Used by killer module to match process names. |
| 0x08058ef5 | FUN_08058ef5 | `util_strchr` | Character search in string (strchr equivalent). |
| 0x08058f30 | FUN_08058f30 | `util_strlen` | String length calculation. |
| 0x08058f5e | FUN_08058f5e | `util_strncpy` | String copy with max length (strncpy equivalent). |
| 0x08053947 | FUN_08053947 | `util_strtol` | String to long conversion with base and sign handling. Used for PID parsing. |
| 0x0805a786 | FUN_0805a786 | `util_atoi` | Simple ASCII to integer (wrapper around strtol with base 10). |
| 0x0805a79a | FUN_0805a79a | `util_strtol` | String to long wrapper. |

### Memory Operations

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08058e92 | FUN_08058e92 | `util_memcpy` | Custom memcpy implementation (copies by dwords, then handles remainder bytes). |
| 0x08058ee0 | FUN_08058ee0 | `util_memset` | Custom memset implementation (fills buffer with byte value). |
| 0x08058f84 | FUN_08058f84 | `util_memcpy_small` | Small memory copy for short buffers. |
| 0x08058f4b | FUN_08058f4b | `util_memset_small` | Small memory set for short buffers. |
| 0x08059668 | FUN_08059668 | `libc_malloc` | Full malloc implementation with bin management, coalescing, and sbrk. |
| 0x08059ed0 | FUN_08059ed0 | `libc_realloc` | realloc implementation that handles resize, move, and free cases. |

### Formatted I/O

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08057a9a | FUN_08057a9a | `util_snprintf` | snprintf wrapper that calls vsnprintf with va_list. |
| 0x08057abb | FUN_08057abb | `util_sprintf` | sprintf wrapper (no size limit). |
| 0x08057ada | FUN_08057ada | `util_vsnprintf` | vsnprintf implementation handling format strings. |
| 0x08058add | FUN_08058add | `util_fscanf` | fscanf implementation for parsing /proc files. |

### File Operations

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08057a82 | FUN_08057a82 | `util_fopen` | fopen wrapper that opens a file with given mode. |
| 0x08057b8c | FUN_08057b8c | `util_fopen_internal` | Internal fopen implementation. |
| 0x08057979 | FUN_08057979 | `util_fclose` | fclose implementation. |
| 0x08057955 | FUN_08057955 | `util_fgets` | fgets implementation (reads line from file). |
| 0x08058afb | FUN_08058afb | `util_fgets_line` | fgets variant for reading lines. |

### System Call Wrappers

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08055995 | FUN_08055995 | `sys_sendto` | sendto syscall wrapper with thread-safety (disables/re-enables signals). |
| 0x08055a51 | FUN_08055a51 | `sys_recvfrom` | recvfrom syscall wrapper with thread-safety. |
| 0x08055bbb | FUN_08055bbb | `sys_read` | read syscall wrapper. |
| 0x08055b0d | FUN_08055b0d | `sys_accept` | accept syscall wrapper. |
| 0x08055c37 | FUN_08055c37 | `sys_nanosleep` | nanosleep syscall wrapper. |
| 0x0805744a | FUN_0805744a | `sys_readlink` | readlink syscall wrapper. Used to read /proc/self/exe and /proc/PID/exe. |
| 0x080570e1 | FUN_080570e1 | `sys_getpgid` | getpgid syscall wrapper. Used to find processes in same process group. |
| 0x0805ac29 | FUN_0805ac29 | `util_usleep` | Microsecond sleep (uses nanosleep with calculated timespec). |

### Threading

| Address | Old Name | New Name | Evidence |
|---------|----------|----------|----------|
| 0x08054474 | FUN_08054474 | `pthread_join` | pthread_join implementation with thread state management. |
| 0x08056286 | FUN_08056286 | `pthread_create` | pthread_create implementation using clone syscall. |

---

## Existing Renames - Validation

All existing renames were validated through code inspection and found to be accurate:

- **Core C2 functions** (`main`, `c2_reconnect`, `c2_packet_validate`, `c2_packet_parse_and_execute`, `toggle_scanner`): Verified against the C2 communication loop in main.
- **Attack infrastructure** (`attack_init`, `attack_method_add`, `attack_start`, `attack_option_find/get_ports/get_ip/get_byte`, `reap_zombie_children`, `stop_attacks_and_kill_all`): Verified against attack dispatch logic.
- **Scanner functions** (`scanner_init`, `scanner_conn_close`, `scanner_get_random_ip`, `scanner_conn_init`, `scanner_main_loop`): Verified - scanner_init forks a child process; scanner_main_loop implements select-based state machine; scanner_get_random_ip filters private/reserved IP ranges.
- **Killer functions** (`killer_init`, `killer_kill_by_stat`, `killer_kill_by_maps`, `killer_kill_by_exe`, `is_suspicious_process`, `is_binary_blacklisted`, `report_and_kill`): Verified - all scan /proc to identify and terminate competing malware.
- **String table functions** (`table_init`, `table_add_entry`): Verified.
- **Utility functions** (`util_rand_next`, `util_rand_fill`, `util_rand_init`, `util_get_local_ip`, `util_checksum_ip`, `util_checksum_tcp_udp`, `util_build_*`, `util_hex_decode`, etc.): All verified against their implementation.
- **System call wrappers** (`sys_*`): All verified as thin wrappers around `int 0x80` syscall instruction.

---

## Analysis Gaps

### Functions Not Confidently Renamed

The following functions in the range 0x0805f325-0x0805f610 appear to be statically linked libc functions (likely stdio internals, locale handling, etc.) that were not identified by name. These are standard library implementations and not malware-specific, so renaming them would provide limited analytical value without full libc symbol recovery.

### Parameters and Variables

The decompiled code uses extensive stack frame manipulation with pointer arithmetic (`puVar10 + offset`), making parameter/variable tracking unreliable without full type recovery. The existing decompiler output uses generic names (`local_*`, `puVar*`, `iStack_*`) which are functional but lack semantic meaning. Key observations:

- **main function**: The `param_1` is `argc` and `param_2` is `argv`. The local variable `local_64` is the C2 password buffer. `local_e4` is the signal mask.
- **attack_method_std**: The `param_1` is target count, `param_2` is target array, `param_3` is option flags byte, `param_4` is options array.
- **scanner_conn_init**: The `param_1` points to a scanner_conn struct. Sets port to 0x1bb (443).

These parameter semantics are consistent with the Gafgyt/Mirai architecture but Ghidra's decompiler loses type information due to the obfuscated stack layout.

---

## Key Findings

1. **Gafgyt/Mirai Botnet Family**: This binary is confirmed as a Gafgyt (Qbot) / Mirai variant based on:
   - Forking architecture (daemonization, killer, scanner, attack processes)
   - XOR-obfuscated string table
   - C2 protocol on port 53537 (0xd121)
   - Single-instance binding on port 8345 (0xd146)
   - Process renaming via `prctl(PR_SET_NAME, ...)` to "scanbot"
   - Banner: "im in deep sorrow."

2. **17 DDoS Attack Methods**: The binary implements 17 distinct attack methods covering:
   - TCP floods (SYN, ACK, STOMP, generic, bypass, Xmas)
   - UDP floods (plain, NUDP, hex, custom, std)
   - Raw socket attacks (IP, OVH, OVH Drop)
   - Application-layer attacks (14 different protocols including HTTP, SSH, TLS, SMTP, MQTT, DNS, NTP, SNMP, Memcached, SSDP, etc.)

3. **Resilience Mechanisms**:
   - Watchdog device interaction to prevent system watchdog from resetting
   - Process group killing via `kill(-pgid, 9)` for self-termination
   - Exponential backoff reconnection to C2 (up to 60 seconds)
   - Zombie process reaping

4. **Scanner**: Scans random IPs (excluding private/reserved ranges) on port 443 (0x1bb), targeting ASUS router vulnerability (applyapp.cgi endpoint).

5. **Killer Module**: Scans /proc to identify and terminate competing malware by:
   - Checking /proc/PID/exe symlink against blacklisted paths
   - Checking /proc/PID/maps for blacklisted memory mappings
   - Checking /proc/PID/stat for blacklisted process names
   - Reporting kills to a reporting server on port 19460 (0x4c04)

6. **Process Hiding**: Renames argv[0] to a fixed string at 0x0805f681 and sets PR_SET_NAME via prctl.
