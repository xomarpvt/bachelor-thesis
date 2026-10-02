import json
from datetime import datetime
from enum import Enum
from typing import Callable


class MessageType(Enum):
    ACK = "ack"  # Server-to-client acknowledgement message
    ATTACK = "attack"  # Attack command message
    COMMAND = "command"  # Generic command message
    HEARTBEAT = "heartbeat"  # Server-to-client heartbeat message


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
        """
        return {
            "status": "...",
            # "notes": "...",   # optional
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a heartbeat message.
        """
        return {
            "sequence": 0,
            # "uptime": 0,   # optional
            # "notes": "...",   # optional
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command message.
        """
        return {
            "command_type": None,
            "payload": data.hex(),
            # "notes": "...",   # optional
        }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Extracts attack-related fields such as attack code, name, protocol,
        duration, arguments, and target information.

        When parsing argv fields, attempt to identify and preserve meaningful
        argument names by mapping protocol-defined positions, flags, or keys
        to descriptive parameter names (e.g., target, port, size, interval, flag).
        Prefer accurate mappings to speculative naming and preserve unknown
        arguments when no reliable key mapping can be determined.
        """

        return {
            "code": 0,
            "name": "",
            "protocol": "",
            "duration": 0,
            "argc": 0,
            "argv": {},
            "num_targets": 0,
            "targets": [],
            # "notes": "...",   # optional
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