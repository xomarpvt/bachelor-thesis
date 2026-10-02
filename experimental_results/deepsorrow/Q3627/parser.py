import json
import socket
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

    ATTACK_METHODS = {
        0x00: ("udp_plain", "UDP"),
        0x01: ("raw", "IP"),
        0x03: ("tcp", "TCP"),
        0x04: ("tcp_ack", "TCP"),
        0x05: ("tcp_stomp", "TCP"),
        0x06: ("hexflood", "UDP"),
        0x07: ("stdhex", "UDP"),
        0x09: ("udphex", "UDP"),
        0x0A: ("tcpxmas", "TCP"),
        0x0B: ("nfo", "UDP"),
        0x0C: ("nudp", "UDP"),
        0x0D: ("tcp_bypass", "TCP"),
        0x0E: ("ovhdrop", "UDP"),
        0x0F: ("ovh", "UDP"),
        0x10: ("std", "UDP"),
        0x11: ("mysql", "TCP"),
        0x12: ("redis", "TCP"),
        0x13: ("minecraft", "TCP"),
        0x14: ("http", "TCP"),
        0x15: ("smtp", "TCP"),
        0x16: ("rdp", "TCP"),
        0x17: ("openvpn", "TCP"),
        0x18: ("fivem", "TCP"),
        0x19: ("mongo", "TCP"),
        0x1A: ("socks5", "TCP"),
    }

    OPTION_NAMES = {
        0x00: "payload_size",
        0x01: "randomize",
        0x02: "tos",
        0x03: "ip_id",
        0x04: "ttl",
        0x05: "df",
        0x06: "src_port",
        0x07: "port_range",
        0x0B: "urg",
        0x0C: "ack",
        0x0D: "psh",
        0x0E: "rst",
        0x0F: "syn",
        0x10: "fin",
        0x11: "seq",
        0x12: "ack_num",
        0x19: "src_ip",
    }

    CONTROL_COMMANDS = {
        0xFF: "toggle_attack",
        0xFE: "kill_children",
        0xFD: "kill_children",
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
        command_type = None

        if len(data) >= 5:
            method_id = data[4]
            if method_id in self.CONTROL_COMMANDS:
                command_type = self.CONTROL_COMMANDS[method_id]

        return {
            "command_type": command_type,
            "payload": data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        if len(data) < 6:
            raise ValueError("Attack message too short")

        command_id = struct.unpack("<I", data[0:4])[0]
        method_id = data[4]
        target_count = data[5]

        method_info = self.ATTACK_METHODS.get(method_id, (f"unknown_{method_id:02x}", "unknown"))
        name = method_info[0]
        protocol = method_info[1]

        offset = 6
        targets = []

        for _ in range(target_count):
            if offset + 5 > len(data):
                break
            ip_int = struct.unpack("!I", data[offset:offset + 4])[0]
            cidr = data[offset + 4]
            ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
            targets.append({
                "ip": ip_str,
                "netmask": cidr,
            })
            offset += 5

        argv = {}

        if offset < len(data):
            option_count = data[offset]
            offset += 1
        else:
            option_count = 0

        for _ in range(option_count):
            if offset + 2 > len(data):
                break
            opt_id = data[offset]
            val_len = data[offset + 1]
            offset += 2

            if offset + val_len > len(data):
                break

            opt_val = data[offset:offset + val_len]
            offset += val_len

            opt_name = self.OPTION_NAMES.get(opt_id, f"opt_{opt_id:02x}")

            try:
                argv[opt_name] = opt_val.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                argv[opt_name] = opt_val.hex()

        return {
            "code": method_id,
            "name": name,
            "protocol": protocol,
            "duration": command_id,
            "argc": len(argv),
            "argv": argv,
            "num_targets": len(targets),
            "targets": targets,
        }

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
