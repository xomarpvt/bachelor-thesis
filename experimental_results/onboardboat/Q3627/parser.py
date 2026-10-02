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
        0x01: ("UDP Flood", "UDP"),
        0x02: ("TCP Flood", "TCP"),
        0x03: ("UDP Hex Flood", "UDP"),
        0x04: ("TCP StdHex", "TCP"),
        0x05: ("TCP SYN", "TCP"),
        0x06: ("Hex Flood", "MIXED"),
        0x07: ("TCP Raw", "TCP"),
        0x08: ("NUDP Flood", "UDP"),
        0x09: ("UDP Plain", "UDP"),
        0x0A: ("Scanner", "MIXED"),
    }

    OPTION_NAMES = {
        0x00: "payload_size",
        0x01: "randomize",
        0x02: "tos",
        0x03: "src_port",
        0x04: "ttl",
        0x05: "df_flag",
        0x06: "src_ip",
        0x07: "dst_port",
        0x0B: "tcp_flags",
        0x0C: "tcp_flag_0c",
        0x0D: "tcp_flag_0d",
        0x0E: "tcp_flag_0e",
        0x0F: "tcp_flag_0f",
        0x10: "tcp_flag_10",
        0x11: "seq_number",
        0x12: "ack_number",
        0x13: "proto_flag",
        0x19: "custom_payload",
        0x1B: "randomize_flag",
        0x1C: "min_payload_size",
        0x1D: "max_payload_size",
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
        status = data[-2:].hex() if len(data) >= 2 else data.hex()
        return {
            "status": status,
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
        if len(data) < 4:
            raise ValueError("Packet too short for attack header")

        payload = data[4:]

        if len(payload) < 7:
            raise ValueError("Insufficient data for attack payload header")

        duration = int.from_bytes(payload[0:4], byteorder="big")
        method_id = payload[4]
        num_targets = payload[5]
        num_options = payload[6]

        method_info = self.ATTACK_METHODS.get(method_id, ("Unknown", "UNKNOWN"))
        name = method_info[0]
        protocol = method_info[1]

        targets_offset = 7
        targets = []
        for _ in range(num_targets):
            if targets_offset + 5 > len(payload):
                break
            ip_bytes = payload[targets_offset:targets_offset + 4]
            ip = ".".join(str(b) for b in ip_bytes)
            port = payload[targets_offset + 4]
            targets.append({
                "ip": ip,
                "port": port,
                "netmask": 32,
            })
            targets_offset += 5

        options_offset = targets_offset
        options = {}
        for _ in range(num_options):
            if options_offset + 8 > len(payload):
                break
            value = int.from_bytes(payload[options_offset:options_offset + 4], byteorder="big")
            option_id = payload[options_offset + 4]
            options[option_id] = value
            options_offset += 8

        argv = {}
        for opt_id, opt_value in options.items():
            key = self.OPTION_NAMES.get(opt_id, f"opt_{opt_id:02x}")
            argv[key] = opt_value

        return {
            "code": method_id,
            "name": name,
            "protocol": protocol,
            "duration": duration,
            "argc": len(argv),
            "argv": argv,
            "num_targets": num_targets,
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
