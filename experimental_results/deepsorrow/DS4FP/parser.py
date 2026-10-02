import struct
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"
    ATTACK = "attack"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"


# Attack method mapping from the specification
ATTACK_METHODS = {
    0x00: ("attack_method_raw", "raw"),
    0x01: ("attack_udp_custom", "udp"),
    0x02: ("attack_method_std", "udp"),
    0x03: ("attack_tcp_ack", "tcp"),
    0x04: ("attack_tcp_syn", "tcp"),
    0x05: ("attack_tcp_stomp", "tcp"),
    0x06: ("attack_method_ovh", "udp"),
    0x07: ("attack_tcp_bypass", "tcp"),
    0x08: ("attack_method_nudp", "udp"),
    0x09: ("attack_method_udphex", "udp"),
    0x0A: ("attack_udp_plain", "udp"),
    0x0B: ("attack_method_stdhex", "udp"),
    0x0C: ("attack_method_nfo", "udp"),
    0x0D: ("attack_method_tcp", "tcp"),
    0x0E: ("attack_method_nudp", "udp"),
    0x0F: ("FUN_0804ca28", "unknown"),
    0x10: ("FUN_0804e100", "unknown"),
    0x11: ("FUN_0804dc4c", "unknown"),
    0x12: ("FUN_0804d697", "unknown"),
    0x13: ("attack_method_std", "udp"),
    0x14: ("attack_application_layer", "application"),
    0x15: ("attack_method_ovhdrop", "udp"),
    0x16: ("util_build_ldap_packet", "ldap"),
    0x17: ("util_build_memcache_packet", "memcache"),
    0x18: ("util_build_ntp_monlist", "ntp"),
    0x19: ("util_build_tftp_packet", "tftp"),
    0x1A: ("util_build_ard_packet", "ard"),
}

# Option ID to argument name mapping
OPTION_NAMES = {
    0x01: "port",
    0x02: "duration",
    0x03: "byte",
    0x04: "int32",
    0x05: "ip",
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

    def parse_ack(self, data: bytes) -> dict:
        """
        Parse an acknowledgement message.

        This protocol does not define ACK messages from the server.
        Returns a generic placeholder.
        """
        return {
            "status": "acknowledged",
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a heartbeat message.

        This protocol does not define server heartbeats.
        Returns a generic placeholder.
        """
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command message.

        For control commands (duration=0, method=0xFE/0xFF) we extract
        the command type. Otherwise, treat as raw payload.
        """
        if len(data) >= 5:
            duration = struct.unpack("!I", data[:4])[0]
            method_id = data[4]
            if duration == 0 and method_id == 0xFE:
                return {
                    "command_type": "stop_attacks",
                    "payload": data.hex(),
                }
            elif duration == 0 and method_id == 0xFF:
                return {
                    "command_type": "toggle_scanner",
                    "payload": data.hex(),
                }
        # Fallback: unknown command
        return {
            "command_type": None,
            "payload": data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Payload format (from specification):
        - 4 bytes: duration (big-endian uint32)
        - 1 byte: method ID
        - 1 byte: num_targets
        - num_targets * 5 bytes: targets (4 bytes IP + 1 byte CIDR)
        - 1 byte: num_options
        - variable: options (each: 1 byte option ID, 1 byte value length, N bytes value)
        """
        if len(data) < 6:
            return {
                "code": 0,
                "name": "",
                "protocol": "",
                "duration": 0,
                "argc": 0,
                "argv": {},
                "num_targets": 0,
                "targets": [],
                "notes": "Malformed packet: too short",
            }

        offset = 0
        duration = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4
        method_id = data[offset]
        offset += 1
        num_targets = data[offset]
        offset += 1

        # Parse targets
        targets = []
        for _ in range(num_targets):
            if offset + 5 > len(data):
                break
            ip_bytes = data[offset:offset+4]
            cidr = data[offset+4]
            ip_str = ".".join(str(b) for b in ip_bytes)
            targets.append({"ip": ip_str, "netmask": cidr})
            offset += 5

        # Parse options
        if offset >= len(data):
            num_options = 0
        else:
            num_options = data[offset]
            offset += 1

        argv = {}
        for _ in range(num_options):
            if offset + 2 > len(data):
                break
            option_id = data[offset]
            val_len = data[offset+1]
            offset += 2
            if offset + val_len > len(data):
                break
            value = data[offset:offset+val_len].decode("ascii", errors="replace")
            offset += val_len

            arg_name = OPTION_NAMES.get(option_id, f"option_{option_id}")
            # Convert numeric values where appropriate
            if option_id in (0x01, 0x02, 0x03, 0x04):
                try:
                    value = int(value)
                except ValueError:
                    pass
            elif option_id == 0x05:
                # IP address string
                pass
            argv[arg_name] = value

        # Map method ID to name and protocol
        method_info = ATTACK_METHODS.get(method_id, (f"unknown_{method_id}", "unknown"))
        name, protocol = method_info

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

    def parse_message(self, timestamp: datetime, source_ip: str, data: bytes, message_type: MessageType) -> dict:
        """
        Parse a received protocol message into a normalized event.

        Selects the parser associated with the message type, handles parsing
        failures by falling back to a generic command representation, and
        enriches attack messages with target IP information.
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

        Applies parse_message() to each input message.
        """
        return [
            self.parse_message(timestamp, host, data, message_type)
            for timestamp, host, data, message_type in messages
        ]
