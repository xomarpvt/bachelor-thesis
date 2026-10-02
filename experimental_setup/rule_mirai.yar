import "elf"

// Helper rule: matches only valid ELF executables or shared objects
private rule ELF_File
{
    condition:
        elf.type == elf.ET_EXEC or
        elf.type == elf.ET_DYN
}

rule Mirai_Generic
{
    meta:
        family      = "Mirai"
        description = "Heuristic detection of Mirai-family ELF malware"
        author      = "analyst"
        reference   = "https://github.com/jgamblin/Mirai-Source-Code"

    strings:
        // Direct identifying strings
        $mirai1 = "Mirai" ascii nocase
        $mirai2 = "mirai.mips" ascii nocase
        $mirai3 = "GETLOCALIP" ascii

        // Typical paths used to disable/kick the hardware watchdog
        $watchdog1 = "/dev/watchdog" ascii
        $watchdog2 = "/dev/misc/watchdog" ascii

        // Well-known hardcoded credentials (original Mirai scanner dictionary)
        $cred1 = "root" ascii
        $cred2 = "admin" ascii
        $cred3 = "xc3511" ascii
        $cred4 = "vizxv" ascii
        $cred5 = "7ujMko0admin" ascii
        $cred6 = "default" ascii nocase

        // Tools/commands used for persistence, propagation and DoS
        $busybox = "busybox" ascii nocase
        $telnet  = "telnet" ascii nocase
        $wget    = "wget" ascii nocase
        $tftp    = "tftp" ascii nocase
        $shell   = "/bin/sh" ascii
        $scanner = "scanner" ascii nocase
        $kill    = "killall" ascii nocase

        // Strings related to DDoS attack modules
        $atk1 = "ackflood" ascii nocase
        $atk2 = "synflood" ascii nocase
        $atk3 = "udpflood" ascii nocase
        $atk4 = "vse" ascii nocase          // Valve Source Engine flood

        // --- C2 / network protocol fingerprints ---
        $c2_probe     = "/bin/busybox MIRAI" ascii   // Probe sent via telnet/SSH to verify BusyBox is present
        $c2_probe_res = "applet not found" ascii     // Expected reply from the compromised device
        $c2_http1     = "GET %s HTTP/1.1" ascii      // HTTP flood module request template
        $c2_http2     = "Accept-Encoding: gzip, deflate" ascii  // HTTP flood header
        $c2_http3     = "Connection: keep-alive" ascii          // HTTP flood header
        $c2_dns1      = "/etc/resolv.conf" ascii     // Reads system DNS resolver config
        $c2_dns2      = "8.8.8.8" ascii              // Hardcoded Google public DNS

    condition:
        ELF_File and
        (
            // Any direct Mirai identifier string
            1 of ($mirai*) or

            // C2 probe fingerprint: very specific, both strings must match
            (
                $c2_probe and $c2_probe_res
            ) or

            // HTTP flood template: at least 2 HTTP strings plus 1 DNS string
            (
                2 of ($c2_http1, $c2_http2, $c2_http3) and
                1 of ($c2_dns1, $c2_dns2)
            ) or

            // Watchdog path combined with at least 2 propagation/shell tools
            (
                1 of ($watchdog1, $watchdog2) and
                2 of ($busybox, $telnet, $wget, $tftp, $shell)
            ) or

            // Three or more of the rarer hardcoded Mirai credentials
            3 of ($cred3, $cred4, $cred5) or

            // Two or more DDoS attack module names
            2 of ($atk1, $atk2, $atk3, $atk4) or

            // Weak generic signals: need many of them together to trigger
            4 of ($busybox, $telnet, $wget, $tftp,
                  $shell, $scanner, $kill, $cred1, $cred2, $cred6)
        )
}