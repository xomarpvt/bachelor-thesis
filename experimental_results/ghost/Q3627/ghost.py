import socket
import time
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    HOST_IP = "94.154.43.158"
    PORT = 2323

    AUTH_TOKEN = b"ghostc2botsecretreuisdhfeuishfuish\r\n"
    PONG_RESPONSE = b"PONG\r\n"

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 60
    RECONNECT_DELAY = 5

    ATTACK_TYPES = frozenset({
        "FIVEM", "VSE", "MCPE", "HEX",
        "UDP", "UDP-BIG", "UDP-PLAIN", "UDP-BYPASS",
        "BANDWIDTH-UDP", "PPS-UDP",
        "BANDWIDTH-TCP", "PPS-TCP", "TCPBYPASS",
        "OVHDROP", "UDPHEX", "OVH", "MIX", "SYN",
        "HTTPGET", "HTTPPOST",
        "BROWSER", "BROWSER-2", "BROWSER-3",
        "MCJAVA", "ADMIN-UDP",
    })

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)

    def connect(self) -> None:
        self.logger.info("Connecting to %s:%d", self.HOST_IP, self.PORT)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.HOST_IP, self.PORT))

        self.logger.info("Connected")

        self._authenticate()

        self.logger.info("Logged in")

    def _authenticate(self) -> None:
        if not self.socket:
            return

        self.logger.debug("Sending auth token")
        self.socket.sendall(self.AUTH_TOKEN)

        arch = "mips"
        os_id = "linux"
        bandwidth = 0.00
        hwaddr = "00:11:22:33:44:55"

        id_string = f"linux.{arch}.{os_id}"
        registration = f"ARCH:{id_string} {bandwidth:.2f}\r\n\r\n{hwaddr}"

        self.logger.debug("Sending registration: %s", registration)
        self.socket.sendall(registration.encode("ascii"))

    def sniff(self) -> Iterable[dict]:
        self.logger.info("Listening ...")

        try:
            while True:
                try:
                    data = self.socket.recv(self.BUFFER_SIZE)
                except socket.timeout:
                    data = b""

                if not data:
                    self.logger.info("Connection closed by server")
                    break

                self.logger.debug("Received %d bytes: %s", len(data), data.hex())

                data = self.preprocess_stream(data)
                self.buffer.extend(data)

                for line in self.extract_lines():
                    message = self.decode_packet(line)
                    message_type = self.get_message_type(message)
                    self.handle_message(message, message_type)

                    parsed_message = self.message_parser.parse_message(
                        timestamp=datetime.now(timezone.utc),
                        source_ip=self.HOST_IP,
                        data=message,
                        message_type=message_type,
                    )

                    self.logger.debug("Parsed: %s", parsed_message)
                    yield parsed_message
        finally:
            if self.socket:
                self.socket.close()
                self.socket = None

    def preprocess_stream(self, data: bytes) -> bytes:
        return data

    def extract_lines(self) -> Iterable[bytes]:
        while b"\n" in self.buffer:
            idx = self.buffer.index(b"\n")
            line = bytes(self.buffer[: idx + 1])
            del self.buffer[: idx + 1]
            yield line

    def decode_packet(self, packet: bytes) -> bytes:
        return packet

    def get_message_type(self, message: bytes) -> MessageType:
        try:
            text = message.decode("ascii").strip()
        except UnicodeDecodeError:
            return MessageType.COMMAND

        if not text:
            return MessageType.COMMAND

        first_token = text.split()[0] if text.split() else ""

        if first_token == "PING":
            return MessageType.HEARTBEAT

        if first_token in self.ATTACK_TYPES:
            return MessageType.ATTACK

        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        if message_type == MessageType.HEARTBEAT and self.socket:
            self.logger.debug("Sending PONG response")
            self.socket.sendall(self.PONG_RESPONSE)
