import socket
import struct
import time
import random
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):
    """
    Gafgyt/Mirai C2 communication module.

    Implements the transport layer as observed in the ARM ELF sample:
    - Non-blocking TCP connect with select-based completion
    - Multi-part login (metadata + password length + password)
    - Length-prefixed command framing (2-byte big-endian)
    - Heartbeat every 60 seconds (6 × 10s select timeout)
    - Reconnection with random delay (1–10 s)
    """

    # C2 endpoint (derived from obfuscated constants)
    HOST_IP = "92.112.127.220"
    PORT = 21242

    # Authentication constants
    DEFAULT_PASSWORD = "unknown"
    PASSWORD = DEFAULT_PASSWORD  # Could be overridden externally

    # Simulated local IP (as would be obtained via UDP connect to 8.8.8.8:13568)
    LOCAL_IP = "10.0.0.2"

    # Protocol constants
    HEARTBEAT_PAYLOAD = b"\x00\x00"
    SELECT_TIMEOUT = 10          # seconds
    HEARTBEAT_INTERVAL = 6       # number of timeouts between heartbeats
    MAX_PAYLOAD_SIZE = 1024
    BUFFER_SIZE = 8192

    # Reconnection delay range
    RECONNECT_DELAY_MIN = 1
    RECONNECT_DELAY_MAX = 10

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self):
        """Establish TCP connection and perform authentication handshake."""
        self.logger.info("Connecting to %s:%d", self.HOST_IP, self.PORT)

        # Create non-blocking socket (simulated via timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.SELECT_TIMEOUT)

        try:
            sock.connect((self.HOST_IP, self.PORT))
        except socket.timeout:
            # Non-blocking connect would return EINPROGRESS; we simulate
            # by catching timeout and then checking connection.
            # In practice, we rely on the blocking connect with timeout.
            pass

        self.socket = sock
        self.logger.info("TCP connection established")

        # Send authentication burst
        self._send_authentication()
        self.logger.info("Authentication sent")

        # Reset heartbeat counter for new session
        self.heartbeat_counter = 0

    def sniff(self):
        """
        Run the command receive loop indefinitely.

        Yields parsed messages from the C2 server.
        """
        self.logger.info("Entering command receive loop")

        while True:
            try:
                # Attempt to read data with timeout
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                # Timeout → heartbeat logic
                self.heartbeat_counter += 1
                if self.heartbeat_counter % self.HEARTBEAT_INTERVAL == 0:
                    self._send_heartbeat()
                continue
            except (socket.error, ConnectionError) as exc:
                self.logger.warning("Connection error: %s", exc)
                self._handle_disconnect()
                # Raise to trigger reconnection via the framework
                raise ConnectionError("C2 connection lost") from exc

            if not data:
                # Graceful close
                self.logger.warning("C2 server closed connection")
                self._handle_disconnect()
                raise ConnectionError("C2 connection closed")

            self.logger.debug("Received %d bytes: %s", len(data), data.hex())

            # Stream preprocessing (none required)
            data = self.preprocess_stream(data)
            self.buffer.extend(data)

            # Extract complete packets from buffer
            for packet in self.extract_packets():
                # Decode (no encryption)
                decoded = self.decode_packet(packet)

                # Extract messages (one per packet in this protocol)
                for message in self.extract_messages(decoded):
                    message_type = self.get_message_type(message)
                    self.handle_message(message, message_type)

                    # Parse and yield
                    parsed = self.message_parser.parse_message(
                        timestamp=datetime.now(timezone.utc),
                        source_ip=self.HOST_IP,
                        data=message,
                        message_type=message_type,
                    )
                    self.logger.debug("Parsed: %s", parsed)
                    yield parsed

    # ------------------------------------------------------------------
    # Protocol-specific methods
    # ------------------------------------------------------------------

    def _send_authentication(self):
        """
        Send the three-part login sequence:
        1. 16-byte metadata block (local IP + zeros)
        2. 1-byte password length
        3. Password string (if length > 0)
        """
        if not self.socket:
            return

        # Part 1: 16-byte metadata
        local_ip_bytes = socket.inet_aton(self.LOCAL_IP)
        metadata = local_ip_bytes + b"\x00" * 12
        self.socket.sendall(metadata)

        # Part 2: password length
        password_bytes = self.PASSWORD.encode()
        pw_len = len(password_bytes)
        self.socket.sendall(struct.pack("!B", pw_len))

        # Part 3: password (if non-empty)
        if pw_len > 0:
            self.socket.sendall(password_bytes)

    def _send_heartbeat(self):
        """Send 2-byte zero keepalive."""
        if self.socket:
            try:
                self.socket.sendall(self.HEARTBEAT_PAYLOAD)
                self.logger.debug("Heartbeat sent")
            except socket.error:
                self.logger.warning("Failed to send heartbeat")

    def _handle_disconnect(self):
        """Close socket and sleep before reconnect."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        delay = random.randint(self.RECONNECT_DELAY_MIN, self.RECONNECT_DELAY_MAX)
        self.logger.info("Reconnecting in %d seconds", delay)
        time.sleep(delay)

    # ------------------------------------------------------------------
    # Template overrides
    # ------------------------------------------------------------------

    def authentication(self):
        """
        Called by the template after connect().
        We already performed authentication inside connect(), so this is a no-op.
        """
        pass

    def heartbeat(self):
        """
        Called by the template every sniff iteration.
        We handle heartbeat via timeout logic, so this is a no-op.
        """
        pass

    def preprocess_stream(self, data: bytes) -> bytes:
        """No stream-level transformations required."""
        return data

    def extract_packets(self) -> Iterable[bytes]:
        """
        Extract length-prefixed packets from the internal buffer.

        Packet format: [2-byte big-endian length][payload]
        """
        while len(self.buffer) >= 2:
            # Read length prefix
            payload_len = struct.unpack("!H", self.buffer[:2])[0]

            if payload_len == 0:
                # Zero-length no-op – discard and continue
                self.buffer = self.buffer[2:]
                continue

            if payload_len > self.MAX_PAYLOAD_SIZE:
                self.logger.warning(
                    "Payload length %d exceeds maximum %d – closing connection",
                    payload_len, self.MAX_PAYLOAD_SIZE
                )
                # Protocol violation: close socket and raise
                self._handle_disconnect()
                raise ConnectionError("Invalid payload length")

            total_len = 2 + payload_len
            if len(self.buffer) < total_len:
                break  # Wait for more data

            packet = bytes(self.buffer[:total_len])
            self.buffer = self.buffer[total_len:]
            yield packet

    def decode_packet(self, packet: bytes) -> bytes:
        """No encryption – return as-is."""
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        """Each packet contains exactly one message (the payload)."""
        if len(packet) < 2:
            return
        payload_len = struct.unpack("!H", packet[:2])[0]
        yield packet[2:2 + payload_len]

    def get_message_type(self, message: bytes) -> MessageType:
        """
        Classify message based on content.

        - 2-byte zero → HEARTBEAT (though server rarely sends this)
        - First 4 bytes zero (KILL command) → COMMAND
        - First 4 bytes non-zero (attack duration) → ATTACK
        - Otherwise → COMMAND (fallback)
        """
        if len(message) == 2 and message == b"\x00\x00":
            return MessageType.HEARTBEAT

        if len(message) >= 4:
            command_id = struct.unpack("!I", message[:4])[0]
            if command_id == 0:
                return MessageType.COMMAND  # KILL command
            else:
                return MessageType.ATTACK   # Attack with duration

        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        Protocol-specific actions.

        Gafgyt/Mirai does not require any ACK or response after receiving
        commands, so this is a no-op.
        """
        pass
