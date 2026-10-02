import struct
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"
    ATTACK = "attack"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"


# Mapping from method_id to (name, protocol)
ATTACK_METHODS = {
    1:  ("std_udp", "UDP"),
    2:  ("udp_std_alt", "UDP"),
    3:  ("udp_plain", "UDP"),
    4:  ("tcp_ack", "TCP"),
    5:  ("tcp_raw", "TCP"),
    6:  ("tcp_syn_custom", "TCP"),
    7:  ("gre_flood", "GRE"),
    8:  ("tcp_stomp", "TCP"),
    9:  ("self_replicate", "SELF"),
    10: ("raw_ip", "RAW"),
}

# Common option IDs observed in Gafgyt/Mirai
OPTION_NAMES = {
    0: "source_port",
    1: "payload",
    2: "length",
    3: "flag",
    4: "interval",
    5: "target_port",
    6: "dport",
    7: "sport",
    8: "domain",
    9: "dns",
}


class MessageParser:

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
    # Parser implementations
    # ------------------------------------------------------------------

    def parse_ack(self, data: bytes) -> dict:
        """
        Parse an acknowledgement message.

        Gafgyt/Mirai does not send explicit ACK messages, so this is a
        placeholder returning a generic success status.
        """
        return {
            "status": "ok",
            "notes": None,
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a heartbeat message.

        The protocol uses 2-byte zero payloads as keepalives.
        We assign a monotonically increasing sequence number.
        """
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
            "uptime": None,
            "notes": None,
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command message.

        Returns the raw payload as a hex string.
        """
        return {
            "command_type": None,
            "payload": data.hex(),
            "notes": None,
        }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Expected format (after length prefix removal):
          [4 bytes] command_id (big-endian uint32) → duration in seconds
          [1 byte]  method_id
          [1 byte]  target_count
          [N*5]     targets (each: 4 bytes IP + 1 byte CIDR)
          [var]     options section (optional)

        Options section:
          [1 byte]  option_count
          for each option:
            [1 byte] option_id
            [1 byte] value_length
            [value_length bytes] value
        """
        if len(data) < 6:
            # Too short to contain header
            return self._fallback_attack(data, "Insufficient data for attack header")

        # Parse header
        duration = struct.unpack("!I", data[0:4])[0]
        method_id = data[4]
        target_count = data[5]

        # Determine attack name and protocol
        method_info = ATTACK_METHODS.get(method_id, (f"unknown_{method_id}", "UNKNOWN"))
        name, protocol = method_info

        offset = 6
        targets = []

        # Parse targets
        if target_count > 0:
            target_size = target_count * 5
            if offset + target_size > len(data):
                return self._fallback_attack(data, f"Expected {target_size} bytes for targets, got {len(data)-offset}")
            for _ in range(target_count):
                ip_bytes = data[offset:offset+4]
                cidr = data[offset+4]
                ip_str = ".".join(str(b) for b in ip_bytes)
                targets.append({"ip": ip_str, "netmask": cidr})
                offset += 5

        # Parse options
        argv = {}
        if offset < len(data):
            option_count = data[offset]
            offset += 1
            for _ in range(option_count):
                if offset + 2 > len(data):
                    break
                opt_id = data[offset]
                val_len = data[offset+1]
                offset += 2
                if offset + val_len > len(data):
                    break
                val = data[offset:offset+val_len]
                offset += val_len

                # Convert value to string (assume ASCII if printable, else hex)
                try:
                    val_str = val.decode("ascii")
                except UnicodeDecodeError:
                    val_str = val.hex()

                # Use meaningful name if known
                param_name = OPTION_NAMES.get(opt_id, f"opt_{opt_id}")
                argv[param_name] = val_str

        return {
            "code": method_id,
            "name": name,
            "protocol": protocol,
            "duration": duration,
            "argc": len(argv),
            "argv": argv,
            "num_targets": len(targets),
            "targets": targets,
            "notes": None,
        }

    def _fallback_attack(self, data: bytes, reason: str) -> dict:
        """
        Return a minimal attack structure when parsing fails.
        """
        return {
            "code": 0,
            "name": "unknown",
            "protocol": "UNKNOWN",
            "duration": 0,
            "argc": 0,
            "argv": {},
            "num_targets": 0,
            "targets": [],
            "notes": f"Parse error: {reason}",
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

        Selects the appropriate parser, handles failures gracefully,
        and enriches attack messages with IP information.
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
            # Fallback to generic command representation
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
                try:
                    info = self.ip_lookup.lookup(target["ip"])
                    message["ip_info"].append(info)
                except Exception:
                    # If lookup fails, skip enrichment
                    pass

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
