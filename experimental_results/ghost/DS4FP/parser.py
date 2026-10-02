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
    Parser for Gafgyt/Mirai variant ("Ghost") C2 protocol messages.

    The protocol is plaintext, newline-delimited. Known message types:
      - PING (heartbeat)
      - Attack commands: <NAME> <TARGET_IP> <PORT> <DURATION>
      - No explicit ACK messages are defined; the parser handles them
        generically for schema completeness.
    """

    # Attack command mapping: name -> (code, protocol)
    ATTACK_MAP = {
        "FIVEM": (1, "udp"),
        "VSE": (2, "udp"),
        "MCPE": (3, "udp"),
        "HEX": (4, "udp"),
        "UDP": (5, "udp"),
        "UDP-BIG": (6, "udp"),
        "UDP-PLAIN": (7, "udp"),
        "UDP-BYPASS": (8, "udp"),
        "BANDWIDTH-UDP": (9, "udp"),
        "PPS-UDP": (10, "udp"),
        "TCP": (11, "tcp"),
        "BANDWIDTH-TCP": (12, "tcp"),
        "PPS-TCP": (13, "tcp"),
        "TCPBYPASS": (14, "tcp"),
        "OVHDROP": (15, "udp"),
        "UDPHEX": (16, "udp"),
        "OVH": (17, "udp"),
        "MIX": (18, "mixed"),
        "SYN": (19, "tcp"),
        "HTTPGET": (20, "tcp"),
        "HTTPPOST": (21, "tcp"),
        "BROWSER": (22, "tcp"),
        "BROWSER-2": (23, "tcp"),
        "BROWSER-3": (24, "tcp"),
        "MCJAVA": (25, "tcp"),
        "ADMIN-UDP": (26, "udp"),
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
        """
        Parse an acknowledgement message.

        The Ghost protocol does not define ACK messages; this implementation
        treats any non-PING, non-attack line as an ACK with the raw content
        as the status.
        """
        raw = data.strip().decode("utf-8", errors="replace")
        return {
            "status": raw if raw else "ack",
            "notes": None,
        }

    def parse_heartbeat(self, data: bytes) -> dict:
        """
        Parse a heartbeat message (PING from C2).

        The protocol uses the literal string "PING" as a keepalive.
        We increment an internal sequence counter for each received PING.
        """
        self.heartbeat_sequence += 1
        return {
            "sequence": self.heartbeat_sequence,
            "uptime": None,
            "notes": None,
        }

    def parse_command(self, data: bytes) -> dict:
        """
        Parse a generic command message (fallback).

        Used when the message type is COMMAND (i.e., not PING and not a
        known attack command). The raw payload is preserved as hex.
        """
        return {
            "command_type": None,
            "payload": data.hex(),
            "notes": None,
        }

    def parse_attack(self, data: bytes) -> dict:
        """
        Parse an attack command message.

        Expected format (space-separated):
            <ATTACK_NAME> <TARGET_IP> <PORT> <DURATION>

        The attack name is looked up in ATTACK_MAP to obtain the code and
        protocol. The target is treated as a single host with netmask 32.
        """
        raw = data.strip().decode("utf-8", errors="replace")
        tokens = raw.split()

        if len(tokens) < 4:
            # Malformed attack command – fall back to generic
            raise ValueError(f"Malformed attack command: {raw!r}")

        name = tokens[0].upper()
        target_ip = tokens[1]
        port_str = tokens[2]
        duration_str = tokens[3]

        # Look up attack metadata
        code, protocol = self.ATTACK_MAP.get(name, (0, "unknown"))

        # Parse duration (clamped by the bot to 3600, but we store raw)
        try:
            duration = int(duration_str)
        except ValueError:
            duration = 0

        # Build argv with meaningful parameter names
        argv = {
            "target": target_ip,
            "port": port_str,
            "duration": duration_str,
        }

        return {
            "code": code,
            "name": name,
            "protocol": protocol,
            "duration": duration,
            "argc": 3,
            "argv": argv,
            "num_targets": 1,
            "targets": [
                {
                    "ip": target_ip,
                    "netmask": 32,
                }
            ],
            "notes": None,
        }

    def parse_message(
        self,
        timestamp: datetime,
        source_ip: str,
        data: bytes,
        message_type: MessageType,
    ) -> dict:
        """
        Parse a received protocol message into a normalized event.

        Selects the parser associated with the message type, handles parsing
        failures by falling back to a generic command representation, and
        enriches attack messages with target IP information.
        """
        message = {
            "timestamp": timestamp.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "source": {"ip": source_ip},
            "message_type": message_type.value,
            "message": {},
            "ip_info": [],
        }

        try:
            parsed = self.parsers[message_type](data)
        except Exception as e:
            # Fall back to generic command representation
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

        Applies parse_message() to each input message.
        """
        return [
            self.parse_message(timestamp, host, data, message_type)
            for timestamp, host, data, message_type in messages
        ]
