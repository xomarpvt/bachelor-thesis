import json
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
    Parser for Gafgyt/Mirai C2 protocol messages.

    Handles attack command parsing according to the binary protocol:
      - 4 bytes: duration (big-endian uint32)
      - 1 byte:  command ID
      - 1 byte:  target count T
      - T*5 bytes: target entries (4 bytes IP + 1 byte CIDR)
      - 1 byte:  option count O
      - variable: option entries (1 byte ID, 1 byte length L, L bytes value)
    """

    # Mapping from command ID to attack name and protocol
    ATTACK_MAP = {
        0x00: ("tcp_stomp", "tcp"),
        0x01: ("udp_plain", "udp"),
        0x02: ("udp_std", "udp"),
        0x03: ("tcp_generic", "tcp"),
        0x04: ("tcp_ack", "tcp"),
        0x05: ("tcp_syn", "tcp"),
        0x06: ("udp_hexflood", "udp"),
        0x07: ("udp_stdhex", "udp"),
        0x08: ("udp_nudp", "udp"),
        0x09: ("udp_udphex", "udp"),
        0x0A: ("tcp_xmas", "tcp"),
        0x0B: ("gre_ip", "gre"),
        0x0C: ("gre_ip", "gre"),
        0x0D: ("udp_dns", "udp"),
        0x0E: ("udp_ovh0e", "udp"),
        0x0F: ("udp_ovh0f", "udp"),
        0x10: ("udp_std10", "udp"),
        0x11: ("udp_std11", "udp"),
        0x12: ("tcp_conn12", "tcp"),
        0x13: ("udp_std13", "udp"),
        0x14: ("udp_std14", "udp"),
        0x15: ("udp_std15", "udp"),
        0x16: ("udp_std16", "udp"),
        0x17: ("tcp_bypass", "tcp"),
        0x18: ("ip_raw", "ip"),
        0x19: ("udp_custom", "udp"),
        0x1A: ("udp_ovhdrop", "udp"),
        0x1B: ("udp_nfo", "udp"),
        0x1C: ("udp_std1c", "udp"),
        0x1D: ("udp_std1d", "udp"),
        0x1E: ("udp_std1e", "udp"),
        0x1F: ("udp_std1f", "udp"),
        0x20: ("udp_ovh", "udp"),
        0x21: ("udp_std21", "udp"),
        0x22: ("udp_std22", "udp"),
        0x26: ("udp_std26", "udp"),
        0x28: ("udp_std28", "udp"),
        0x2A: ("udp_std2a", "udp"),
    }

    # Best-effort mapping of option IDs to argument names
    # Based on common Mirai/Gafgyt option conventions
    OPTION_NAMES = {
        0: "port",
        1: "duration",
        2: "flags",
        3: "size",
        4: "interval",
        5: "pps",
        6: "source_port",
        7: "data",
        8: "domain",
        9: "type",
        10: "count",
        11: "method",
    }

    def __init__(self, ip_lookup):
        self.heartbeat_sequence = 0
        self.ip_lookup = ip_lookup

        self.parsers: dict[MessageType, Callable[[bytes], dict]] = {
            MessageType.ACK: self.parse_ack,
            MessageType.HEARTBEAT: self.parse_heartbeat,
            MessageType.COMMAND: self.parse_command,
            MessageType.ATTACK: self.parse_attack,
        }

    # ------------------------------------------------------------------
    # Message-type parsers
    # ------------------------------------------------------------------

    def parse_ack(self, data: bytes) -> dict:
        """
        Parse an acknowledgement message.

        The Gafgyt/Mirai protocol does not define explicit ACK messages,
        so this is a stub. If data is present, treat it as a status string.
        """
        status = data.decode("utf-8", errors="replace").strip() if data else "acknowledged"
        return {
            "status": status,
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a server heartbeat message.

        The server heartbeat consists of a 2-byte zero length prefix followed
        by 2 bytes of data (discarded by the bot). The data may contain a
        sequence number or other metadata. We extract it as a sequence number.
        """
        seq = 0
        if len(data) >= 2:
            seq = int.from_bytes(data[:2], "big")
        self.heartbeat_sequence += 1
        return {
            "sequence": seq,
            "uptime": None,
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command message.

        Special command IDs (0xFF = KILL, 0xFE = UPDATE) are handled here.
        For all other commands, the raw payload is returned.
        """
        if len(data) < 5:
            return {
                "command_type": None,
                "payload": data.hex(),
            }

        command_id = data[4]
        if command_id == 0xFF:
            return {
                "command_type": "KILL",
                "payload": data.hex(),
                "notes": "Kill all running attacks",
            }
        elif command_id == 0xFE:
            # UPDATE command: payload after offset 5 is a URL
            url = data[5:].decode("utf-8", errors="replace") if len(data) > 5 else ""
            return {
                "command_type": "UPDATE",
                "payload": url,
                "notes": "Download and execute new binary",
            }
        else:
            return {
                "command_type": None,
                "payload": data.hex(),
            }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Extracts duration, command ID, targets, and options according to
        the binary protocol.
        """
        if len(data) < 6:
            # Too short for a valid attack command
            return {
                "code": 0,
                "name": "unknown",
                "protocol": "unknown",
                "duration": 0,
                "argc": 0,
                "argv": {},
                "num_targets": 0,
                "targets": [],
                "notes": "Payload too short for attack parsing",
            }

        # Duration: first 4 bytes as big-endian uint32
        duration = int.from_bytes(data[0:4], "big")

        # Command ID
        command_id = data[4]

        # Look up attack name and protocol
        name, protocol = self.ATTACK_MAP.get(command_id, ("unknown", "unknown"))

        # Target count
        target_count = data[5]
        offset = 6

        # Parse targets
        targets = []
        for _ in range(target_count):
            if offset + 5 > len(data):
                break
            ip_bytes = data[offset:offset+4]
            cidr = data[offset+4]
            ip_str = ".".join(str(b) for b in ip_bytes)
            targets.append({"ip": ip_str, "netmask": cidr})
            offset += 5

        # Option count
        if offset >= len(data):
            option_count = 0
        else:
            option_count = data[offset]
            offset += 1

        # Parse options
        argv = {}
        argc = 0
        for _ in range(option_count):
            if offset + 2 > len(data):
                break
            option_id = data[offset]
            value_len = data[offset+1]
            offset += 2
            if offset + value_len > len(data):
                break
            value_bytes = data[offset:offset+value_len]
            offset += value_len

            # Convert value to string (try UTF-8, fallback to hex)
            try:
                value_str = value_bytes.decode("utf-8")
            except UnicodeDecodeError:
                value_str = value_bytes.hex()

            # Map option ID to a descriptive name
            arg_name = self.OPTION_NAMES.get(option_id, f"arg_{option_id}")
            argv[arg_name] = value_str
            argc += 1

        return {
            "code": command_id,
            "name": name,
            "protocol": protocol,
            "duration": duration,
            "argc": argc,
            "argv": argv,
            "num_targets": len(targets),
            "targets": targets,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_message(
        self,
        timestamp: datetime,
        source_ip: str,
        data: bytes,
        message_type: MessageType,
    ) -> dict:
        """
        Parse a received protocol message into a normalized event.

        Delegates to the appropriate parser based on message_type.
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

        # Enrich attack messages with IP lookup data
        if message_type == MessageType.ATTACK:
            for target in parsed.get("targets", []):
                message["ip_info"].append(self.ip_lookup.lookup(target["ip"]))

        return message

    def parse_message_batch(
        self,
        messages: list[tuple[datetime, str, bytes, MessageType]],
    ) -> list[dict]:
        """
        Parse multiple messages into normalized events.
        """
        return [
            self.parse_message(timestamp, host, data, message_type)
            for timestamp, host, data, message_type in messages
        ]
