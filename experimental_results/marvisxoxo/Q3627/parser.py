import socket
import struct
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"  # Server-to-client acknowledgement message
    ATTACK = "attack"  # Attack command message
    COMMAND = "command"  # Generic command message
    HEARTBEAT = "heartbeat"  # Server-to-client heartbeat message


class MessageParser:

    METHOD_MAP = {
        1: ("UDP Generic Flood", "UDP"),
        2: ("UDP Plain Flood", "UDP"),
        3: ("TCP SYN Flood", "TCP"),
        4: ("TCP ACK Flood", "TCP"),
        5: ("TCP Socket Flood", "TCP"),
        6: ("UDP OpenVPN Flood", "UDP"),
        7: ("UDP Connect Flood", "UDP"),
        8: ("UDP Ragnarok Flood", "UDP"),
    }

    OPTION_MAP = {
        0: "payload_size",
        1: "randomize_payload",
        2: "ttl",
        3: "source_port",
        4: "df_flag",
        5: "ecn",
        6: "dest_port",
        7: "source_port_2",
        0xb: "fin_flag",
        0xc: "urg_flag",
        0xd: "ack_flag",
        0xe: "psh_flag",
        0xf: "rst_flag",
        0x10: "syn_flag",
        0x11: "ttl_override",
        0x12: "window_size",
        0x19: "spoofed_source_ip",
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

    def parse_ack(self, data: bytes) -> dict:
        return {
            "status": "acknowledged",
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
        }

    def parse_command(self, data: bytes) -> dict:
        return {
            "command_type": None,
            "payload": data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        if len(data) < 6:
            raise ValueError("Attack message too short")

        duration = struct.unpack('>I', data[0:4])[0]
        method_id = data[4]
        target_count = data[5]

        if target_count == 0:
            raise ValueError("No targets specified")

        min_length = 6 + target_count * 5
        if len(data) < min_length:
            raise ValueError("Attack message truncated before targets")

        method_name, protocol = self.METHOD_MAP.get(
            method_id, (f"Unknown_{method_id}", "UNKNOWN")
        )

        targets = []
        offset = 6
        for _ in range(target_count):
            target_ip = socket.inet_ntoa(data[offset:offset + 4])
            targets.append({
                "ip": target_ip,
                "netmask": 32,
            })
            offset += 5

        argv = {}
        option_count = 0

        if offset + 4 <= len(data):
            option_count = struct.unpack('>I', data[offset:offset + 4])[0]
            offset += 4

            for _ in range(option_count):
                if offset >= len(data):
                    break

                option_length = data[offset]
                offset += 1

                if offset + option_length > len(data):
                    break

                option_value = data[offset:offset + option_length]
                offset += option_length

                if offset >= len(data):
                    break

                option_id = data[offset]
                offset += 1

                param_name = self.OPTION_MAP.get(
                    option_id, f"option_{option_id:x}"
                )

                argv[param_name] = self._parse_option_value(option_value)

        return {
            "code": method_id,
            "name": method_name,
            "protocol": protocol,
            "duration": duration,
            "argc": len(argv),
            "argv": argv,
            "num_targets": target_count,
            "targets": targets,
        }

    def _parse_option_value(self, value: bytes) -> object:
        try:
            decoded = value.decode('ascii')
            if decoded.isdigit():
                return int(decoded)
            return decoded
        except (UnicodeDecodeError, ValueError):
            return value.hex()

    def parse_message(self, timestamp: datetime, source_ip: str, data: bytes, message_type: MessageType) -> dict:
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
        return [
            self.parse_message(timestamp, host, data, message_type)
            for timestamp, host, data, message_type in messages
        ]
