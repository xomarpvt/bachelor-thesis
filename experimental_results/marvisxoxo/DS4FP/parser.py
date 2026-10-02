import json
import struct
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"
    ATTACK = "attack"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"


class MessageParser:
    """
    Parser for Gafgyt/Qbot (marvisxoxo) C2 protocol messages.

    Handles ACK (authentication acknowledgment), HEARTBEAT (server heartbeat),
    COMMAND (fallback), and ATTACK (command packets with targets and options).
    """

    # Attack method dispatch table (method_id -> (name, protocol))
    ATTACK_METHODS = {
        0: ("udp_generic", "UDP"),
        1: ("udp_plain", "UDP"),
        2: ("tcp_syn", "TCP"),
        3: ("tcp_ack", "TCP"),
        4: ("tcp_socket", "TCP"),
        5: ("udp_openvpn", "UDP"),
        6: ("udp_ragnarok", "UDP"),
        7: ("udp_ragnarok", "UDP"),
    }

    # Option ID to descriptive name mapping
    OPTION_NAMES = {
        0: "payload_size",
        1: "payload_rand",
        2: "payload_hex",
        3: "source_port",
        4: "domain",
        5: "payload_file",
        6: "tcp_window",
        7: "tcp_ttl",
        8: "tcp_seq",
        9: "tcp_ack",
        10: "tcp_sport",
        11: "tcp_dport",
        12: "tcp_urg_ptr",
        13: "tcp_opt",
        14: "ip_tos",
        15: "ip_ident",
        16: "ip_ttl",
        17: "ip_df",
        18: "udp_sport",
        19: "udp_dport",
        20: "duration",
        21: "attack_cmd",
        22: "gre_ver",
        23: "gre_prot",
        24: "gre_key",
        25: "gre_seq",
        26: "dns_domain",
        27: "dns_type",
    }

    # Server authentication acknowledgment header (18 bytes)
    SERVER_AUTH_HEADER = bytes([
        0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01, 0x03,
        0x02, 0x0E, 0x0A, 0x0D, 0x0E, 0x03, 0x02, 0x00,
        0x0A, 0x0B
    ])

    def __init__(self, ip_lookup):
        self.heartbeat_sequence = 0
        self.ip_lookup = ip_lookup

        self.parsers: dict[MessageType, Callable[[bytes], dict]] = {
            MessageType.ACK: self.parse_ack,
            MessageType.HEARTBEAT: self.parse_heartbeat,
            MessageType.COMMAND: self.parse_command,
            MessageType.ATTACK: self.parse_attack,
        }

    # ------------------------------------------------------------------ #
    #  Parser implementations                                            #
    # ------------------------------------------------------------------ #

    def parse_ack(self, data: bytes) -> dict:
        """
        Parse an authentication acknowledgment.

        The server sends the 18-byte AUTH_HEADER_SERVER after successful
        authentication. We treat this as an ACK with status "authenticated".
        """
        return {
            "status": "authenticated",
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a server heartbeat message.

        The protocol does not define a server-to-client heartbeat format;
        this is a placeholder for completeness. Returns a default sequence.
        """
        return {
            "sequence": 0,
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command (fallback for unrecognised messages).
        """
        return {
            "command_type": None,
            "payload": data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Binary format (after XOR decryption):
        - 4 bytes: primary target IP (big-endian)
        - 1 byte: method_id
        - 1 byte: target_count (N)
        - N * 5 bytes: target entries (4 bytes IP + 1 byte CIDR)
        - Remaining: options (1 byte opt_count, then for each option:
          1 byte id, 1 byte len, L bytes value)
        """
        if len(data) < 6:
            # Too short for header
            return self._fallback_attack(data)

        # Parse primary target IP
        primary_ip_int = struct.unpack(">I", data[0:4])[0]
        primary_ip = self._int_to_ip(primary_ip_int)

        method_id = data[4]
        target_count = data[5]

        # Minimum length: 6 + target_count * 5
        min_len = 6 + target_count * 5
        if len(data) < min_len:
            return self._fallback_attack(data)

        # Parse targets
        targets = []
        # Include primary target with /32 netmask
        targets.append({"ip": primary_ip, "netmask": 32})

        offset = 6
        for _ in range(target_count):
            ip_int = struct.unpack(">I", data[offset:offset+4])[0]
            ip = self._int_to_ip(ip_int)
            cidr = data[offset+4]
            targets.append({"ip": ip, "netmask": cidr})
            offset += 5

        # Parse options
        options = {}
        duration = 0
        if offset < len(data):
            opt_count = data[offset]
            offset += 1
            for _ in range(opt_count):
                if offset + 2 > len(data):
                    break
                opt_id = data[offset]
                opt_len = data[offset+1]
                if offset + 2 + opt_len > len(data):
                    break
                opt_val = data[offset+2:offset+2+opt_len]
                offset += 2 + opt_len

                # Convert value to appropriate type
                name = self.OPTION_NAMES.get(opt_id, f"opt_{opt_id}")
                if opt_id in (0, 3, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 18, 19, 20, 22, 23, 24, 25, 27):
                    # Integer options
                    if opt_len == 1:
                        val = opt_val[0]
                    elif opt_len == 2:
                        val = struct.unpack("<H", opt_val)[0]
                    elif opt_len == 4:
                        val = struct.unpack("<I", opt_val)[0]
                    else:
                        val = int.from_bytes(opt_val, 'little')
                elif opt_id in (1, 17):
                    # Flag options (boolean)
                    val = bool(opt_val[0]) if opt_len else False
                else:
                    # String options
                    val = opt_val.decode('utf-8', errors='replace')

                options[name] = val
                if opt_id == 20:
                    duration = val

        # Build argv from options (excluding duration which is top-level)
        argv = {k: v for k, v in options.items() if k != "duration"}

        # Get attack name and protocol
        name, protocol = self.ATTACK_METHODS.get(method_id, ("unknown", "unknown"))

        return {
            "code": method_id,
            "name": name,
            "protocol": protocol,
            "duration": duration,
            "argc": len(argv),
            "argv": argv,
            "num_targets": len(targets),
            "targets": targets,
        }

    def _fallback_attack(self, data: bytes) -> dict:
        """
        Return a minimal attack representation when parsing fails.
        """
        return {
            "code": 0,
            "name": "unknown",
            "protocol": "unknown",
            "duration": 0,
            "argc": 0,
            "argv": {},
            "num_targets": 0,
            "targets": [],
            "notes": f"Failed to parse attack packet (len={len(data)})",
        }

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    def parse_message(self, timestamp: datetime, source_ip: str, data: bytes, message_type: MessageType) -> dict:
        """
        Parse a received protocol message into a normalized event.

        Falls back to COMMAND on parser failure.
        """
        message = {
            "timestamp": timestamp.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "source": {"ip": source_ip},
            "message_type": message_type.value,
            "message": {},
            "ip_info": [],
        }

        try:
            parsed = self.parsers[message_type](data)
        except Exception as e:
            message["message_type"] = MessageType.COMMAND.value
            message["message"] = {
                "command_type": None,
                "payload": data.hex(),
                "notes": f"Failed to parse as {message_type.value}: {e}",
            }
            return message

        message["message"] = parsed

        if message_type == MessageType.ATTACK:
            for target in parsed.get("targets", []):
                message["ip_info"].append(self.ip_lookup.lookup(target["ip"]))

        return message

    def parse_message_batch(self, messages: list[tuple[datetime, str, bytes, MessageType]]) -> list[dict]:
        """
        Parse multiple messages into normalized events.
        """
        return [
            self.parse_message(timestamp, host, data, message_type)
            for timestamp, host, data, message_type in messages
        ]

    # ------------------------------------------------------------------ #
    #  Helpers                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _int_to_ip(ip_int: int) -> str:
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
