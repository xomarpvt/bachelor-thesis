import socket
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):
    """Gafgyt/Mirai variant ("Ghost") C2 communication module."""

    HOST_IP = "94.154.43.158"  # Default C2 address
    PORT = 2323                # Default C2 port

    # Authentication token sent immediately after TCP connect
    HANDSHAKE = b"ghostc2botsecretreuisdhfeuishfuish\r\n"  # 36 bytes

    # Simulated system profile (no real host fingerprinting)
    PROFILE = b"ARCH:linux.mips.LINUX_2.6 0.00\r\n"

    # PONG response
    PONG = b"PONG\r\n"

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = None  # Blocking mode (as per spec)

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self):
        """Establish TCP connection, send authentication token and profile."""
        self.logger.info(f"Connecting to {self.HOST_IP}:{self.PORT}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.SOCKET_TIMEOUT is not None:
            self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.HOST_IP, self.PORT))

        self.logger.info("Connected")

        # Phase 2: send login token
        self._send_all(self.HANDSHAKE)
        self.logger.debug("Sent authentication token")

        # Phase 3: send simulated system profile
        self._send_all(self.PROFILE)
        self.logger.debug("Sent system profile")

        self.logger.info("Session established")

    def sniff(self):
        """Receive and process C2 commands indefinitely."""
        self.logger.info("Listening for commands ...")

        while True:
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                # No data within timeout – continue (no heartbeat in this protocol)
                continue

            if not data:
                # Connection closed by server
                self.logger.warning("Connection closed by C2")
                self.socket.close()
                return  # Will trigger reconnection in the outer loop

            self.logger.debug("Received %d bytes: %s", len(data), data.hex())

            # Stream preprocessing (no transformation needed)
            data = self.preprocess_stream(data)
            self.buffer.extend(data)

            # Extract complete lines (packets) from buffer
            for packet in self.extract_packets():
                # No decryption/decoding needed
                packet = self.decode_packet(packet)

                # Each line is a single message
                for message in self.extract_messages(packet):
                    message_type = self.get_message_type(message)
                    self.handle_message(message, message_type)

                    # Parse and yield the message
                    parsed = self.message_parser.parse_message(
                        timestamp=datetime.now(timezone.utc),
                        source_ip=self.HOST_IP,
                        data=message,
                        message_type=message_type,
                    )
                    self.logger.debug("Parsed: %s", parsed)
                    yield parsed

    # ------------------------------------------------------------------
    # Protocol-specific overrides
    # ------------------------------------------------------------------

    def preprocess_stream(self, data: bytes) -> bytes:
        """No stream-level transformation required."""
        return data

    def extract_packets(self) -> Iterable[bytes]:
        """Extract newline-delimited packets from the receive buffer."""
        while True:
            idx = self.buffer.find(b"\n")
            if idx == -1:
                break
            # Include the newline in the packet
            packet = bytes(self.buffer[: idx + 1])
            del self.buffer[: idx + 1]
            yield packet

    def decode_packet(self, packet: bytes) -> bytes:
        """No decryption or decoding needed."""
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        """Each packet is a single message."""
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        """
        Classify the message based on its content.
        - PING → HEARTBEAT (server keepalive)
        - Attack commands → ATTACK
        - Everything else → COMMAND (fallback)
        """
        # Remove trailing whitespace for tokenization
        stripped = message.strip()
        if not stripped:
            return MessageType.COMMAND

        # First token (command name)
        tokens = stripped.split(b" ", 1)
        cmd = tokens[0].upper()

        if cmd == b"PING":
            return MessageType.HEARTBEAT

        # Known attack command names (from specification)
        attack_commands = {
            b"FIVEM", b"VSE", b"MCPE", b"HEX", b"UDP", b"UDP-BIG",
            b"UDP-PLAIN", b"UDP-BYPASS", b"BANDWIDTH-UDP", b"PPS-UDP",
            b"TCP", b"BANDWIDTH-TCP", b"PPS-TCP", b"TCPBYPASS",
            b"OVHDROP", b"UDPHEX", b"OVH", b"MIX", b"SYN",
            b"HTTPGET", b"HTTPPOST", b"BROWSER", b"BROWSER-2",
            b"BROWSER-3", b"MCJAVA", b"ADMIN-UDP",
        }
        if cmd in attack_commands:
            return MessageType.ATTACK

        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        Respond to protocol messages.
        - PING → send PONG
        - Attack commands → no response (just yield)
        - Unknown → ignore
        """
        if message_type == MessageType.HEARTBEAT:
            self._send_all(self.PONG)
            self.logger.debug("Sent PONG")

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _send_all(self, data: bytes) -> None:
        """Send all bytes, handling partial sends."""
        if not self.socket:
            return
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = self.socket.send(data[total_sent:])
            except socket.error as e:
                self.logger.error("Send error: %s", e)
                return
            if sent == 0:
                self.logger.error("Send returned 0 – connection lost")
                return
            total_sent += sent
