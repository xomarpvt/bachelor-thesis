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

    ATTACK_PROTOCOL_MAP = {
        "UDP": "UDP",
        "UDP-BIG": "UDP",
        "UDP-PLAIN": "UDP",
        "UDP-BYPASS": "UDP",
        "BANDWIDTH-UDP": "UDP",
        "PPS-UDP": "UDP",
        "OVHDROP": "UDP",
        "UDPHEX": "UDP",
        "OVH": "UDP",
        "BANDWIDTH-TCP": "TCP",
        "PPS-TCP": "TCP",
        "TCPBYPASS": "TCP",
        "MIX": "TCP",
        "SYN": "RAW",
        "FIVEM": "UDP",
        "VSE": "UDP",
        "MCPE": "UDP",
        "HEX": "UDP",
        "HTTPGET": "HTTP",
        "HTTPPOST": "HTTP",
        "BROWSER": "HTTP",
        "BROWSER-2": "HTTP",
        "BROWSER-3": "HTTP",
        "MCJAVA": "TCP",
        "ADMIN-UDP": "UDP",
    }

    ATTACK_CODE_MAP = {
        "FIVEM": 1,
        "VSE": 2,
        "MCPE": 3,
        "HEX": 4,
        "UDP": 5,
        "UDP-BIG": 6,
        "UDP-PLAIN": 7,
        "UDP-BYPASS": 8,
        "BANDWIDTH-UDP": 9,
        "PPS-UDP": 10,
        "BANDWIDTH-TCP": 11,
        "PPS-TCP": 12,
        "TCPBYPASS": 13,
        "OVHDROP": 14,
        "UDPHEX": 15,
        "OVH": 16,
        "MIX": 17,
        "SYN": 18,
        "HTTPGET": 19,
        "HTTPPOST": 20,
        "BROWSER": 21,
        "BROWSER-2": 22,
        "BROWSER-3": 23,
        "MCJAVA": 24,
        "ADMIN-UDP": 25,
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
        text = data.decode("ascii", errors="replace").strip()
        return {
            "status": text if text else "ack",
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
        }

    def parse_command(self, data: bytes) -> dict:
        text = data.decode("ascii", errors="replace").strip()
        return {
            "command_type": None,
            "payload": text if text else data.hex(),
        }

    def parse_attack(self, data: bytes) -> dict:
        text = data.decode("ascii", errors="replace").strip()
        tokens = text.split()

        if len(tokens) < 4:
            raise ValueError(f"Attack command requires at least 4 tokens, got {len(tokens)}")

        attack_name = tokens[0]
        target_ip = tokens[1]
        port_str = tokens[2]
        duration_str = tokens[3]

        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port value: {port_str}")

        try:
            duration = int(duration_str)
        except ValueError:
            raise ValueError(f"Invalid duration value: {duration_str}")

        if duration > 3600:
            duration = 3600

        protocol = self.ATTACK_PROTOCOL_MAP.get(attack_name, "UNKNOWN")
        code = self.ATTACK_CODE_MAP.get(attack_name, 0)

        argv = {
            "target": target_ip,
            "port": port,
            "duration": duration,
        }

        targets = [
            {
                "ip": target_ip,
                "netmask": 32,
            }
        ]

        return {
            "code": code,
            "name": attack_name,
            "protocol": protocol,
            "duration": duration,
            "argc": 3,
            "argv": argv,
            "num_targets": 1,
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
