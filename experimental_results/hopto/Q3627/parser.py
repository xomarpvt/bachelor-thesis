import json
import struct
import socket
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"
    ATTACK = "attack"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"


ATTACK_METHODS = {
    0x00: ("TCP SYN Flood", "TCP"),
    0x01: ("TCP DNS Amplification", "TCP"),
    0x02: ("TCP Random Flag Flood", "TCP"),
    0x03: ("TCP Random Attack", "TCP"),
    0x04: ("TCP Multi-Flag Flood", "TCP"),
    0x05: ("TCP Stomp", "TCP"),
    0x06: ("TCP Hex Flood", "TCP"),
    0x07: ("TCP Standard Hex Flood", "TCP"),
    0x08: ("NUDP Flood", "UDP"),
    0x09: ("UDP Hex Flood", "UDP"),
    0x0a: ("TCP Xmas Flood", "TCP"),
    0x0b: ("TCP Unknown", "TCP"),
    0x0c: ("HTTP Flood", "HTTP"),
    0x0d: ("Mixed Protocol Attack", "MIXED"),
    0x0e: ("OVH Drop Flood", "TCP"),
    0x0f: ("NFO Flood", "TCP"),
    0x10: ("OVH Raw Flood", "TCP"),
    0x11: ("NFO v2 Flood", "TCP"),
    0x12: ("UDP NDNP Flood", "UDP"),
    0x13: ("NMEM Attack", "TCP"),
    0x14: ("NMSG Attack", "TCP"),
    0x15: ("NUCG Attack", "TCP"),
    0x16: ("TWAMP Attack", "TCP"),
    0x17: ("TCP OVH Bypass", "TCP"),
    0x18: ("TCP Options Flood", "TCP"),
    0x19: ("Teamspeak UDP Flood", "UDP"),
    0x1a: ("OVH TCP Flood", "TCP"),
    0x1b: ("TCP Bypass Flood", "TCP"),
    0x1c: ("SSDP Flood", "UDP"),
    0x1d: ("DNS Flood", "UDP"),
    0x1e: ("UDP Custom Flood", "UDP"),
    0x1f: ("TLA Attack", "TCP"),
    0x20: ("HTTP Attack", "HTTP"),
    0x21: ("TCP SYN Proxy Flood", "TCP"),
    0x22: ("SLA Attack", "TCP"),
    0x26: ("MySQL Flood", "TCP"),
    0x28: ("Teamspeak Attack", "UDP"),
    0x2a: ("UDP Flood", "UDP"),
}

OPTION_NAMES = {
    0x00: "size",
    0x01: "flag",
    0x06: "src_port",
    0x07: "dst_port",
    0x08: "host",
    0x14: "user_agent",
    0x15: "count",
    0x16: "path",
    0x18: "threads",
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
        return {
            "status": "received",
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
        }

    def parse_command(self, data: bytes) -> dict:
        command_type = None

        if len(data) >= 5:
            method_id = struct.unpack('b', data[4:5])[0]
            if method_id == -1:
                command_type = "kill_attack"
            elif method_id == -2:
                command_type = "update"

        return {
            "command_type": command_type,
            "payload": data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        if len(data) < 6:
            raise ValueError("Attack payload too short")

        duration = struct.unpack('!I', data[0:4])[0]
        method_id = data[4]
        target_count = data[5]

        attack_name, protocol = ATTACK_METHODS.get(method_id, (f"Unknown_{method_id:02x}", "UNKNOWN"))

        offset = 6
        targets = []

        if offset + target_count * 5 > len(data):
            raise ValueError("Insufficient data for targets")

        for i in range(target_count):
            target_ip_raw = data[offset:offset + 4]
            target_cidr = data[offset + 4]
            target_ip = socket.inet_ntoa(target_ip_raw)
            targets.append({
                "ip": target_ip,
                "netmask": target_cidr,
            })
            offset += 5

        option_count = 0
        argv = {}

        if offset < len(data):
            option_count = data[offset]
            offset += 1

            for _ in range(option_count):
                if offset + 2 > len(data):
                    break

                option_id = data[offset]
                option_len = data[offset + 1]
                offset += 2

                if offset + option_len > len(data):
                    break

                option_value = data[offset:offset + option_len]
                offset += option_len

                key = OPTION_NAMES.get(option_id, f"opt_{option_id:02x}")
                if option_len == 1:
                    argv[key] = option_value[0]
                else:
                    try:
                        argv[key] = option_value.decode('utf-8', errors='replace')
                    except Exception:
                        argv[key] = option_value.hex()

        return {
            "code": method_id,
            "name": attack_name,
            "protocol": protocol,
            "duration": duration,
            "argc": len(argv),
            "argv": argv,
            "num_targets": target_count,
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
