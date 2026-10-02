import socket
import struct
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    # C2 endpoint (hardcoded from binary analysis)
    HOST_IP = "62.60.159.184"
    PORT = 18129

    # Login credentials (simulated; real bot takes from argv[1])
    PASSWORD = b"test"  # max 31 bytes

    # Protocol constants
    LOGIN_MAGIC = b"\x00\x00\x00\x01"
    ARCH_TYPE = b"\x03"
    ARCH_STRING = b"x86"

    HEARTBEAT = b"\x00\x00"

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 30  # seconds, matches select timeout
    MAX_PACKET_SIZE = 0x2000  # 8192
    MAX_HEARTBEATS = 119  # after 120th timeout, reconnect

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0
        self._reconnect_backoff = 1  # seconds

    def connect(self):
        """Establish connection and perform login handshake."""
        self.logger.info(f"Connecting to C2 at {self.HOST_IP}:{self.PORT}")

        # Retry with exponential backoff (max 60s)
        while True:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.SOCKET_TIMEOUT)

                # Apply socket options as in the original binary
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # TCP_QUICKACK is Linux-specific; fallback if not available
                try:
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                except AttributeError:
                    pass
                # IP_TOS = 3
                try:
                    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 3)
                except OSError:
                    pass

                self.socket.connect((self.HOST_IP, self.PORT))
                break  # success
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                self.logger.warning(f"Connection failed: {e}. Retrying in {self._reconnect_backoff}s")
                import time
                time.sleep(self._reconnect_backoff)
                self._reconnect_backoff = min(self._reconnect_backoff * 2, 60)
                if self.socket:
                    self.socket.close()
                    self.socket = None
                continue

        self.logger.info("Connected, sending login handshake")
        self.authentication()
        self.heartbeat_counter = 0
        self._reconnect_backoff = 1
        self.logger.info("Login complete, entering command loop")

    def authentication(self):
        """Send the login handshake (magic, password, architecture)."""
        if not self.socket:
            return

        # Segment 1: 4-byte magic
        self.socket.sendall(self.LOGIN_MAGIC)

        # Segment 2: password length (1 byte)
        pw_len = len(self.PASSWORD)
        self.socket.sendall(struct.pack("!B", pw_len))

        # Segment 3: password bytes (if any)
        if pw_len > 0:
            self.socket.sendall(self.PASSWORD)

        # Segment 4: architecture type (1 byte)
        self.socket.sendall(self.ARCH_TYPE)

        # Segment 5: architecture string (3 bytes)
        self.socket.sendall(self.ARCH_STRING)

    def sniff(self):
        """Main receive loop: process incoming commands, send heartbeats on timeout."""
        self.logger.info("Listening for commands...")

        while True:
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                # No data received within 30 seconds -> send heartbeat
                self.heartbeat()
                self.heartbeat_counter += 1
                if self.heartbeat_counter > self.MAX_HEARTBEATS:
                    self.logger.warning("Too many heartbeats without data, reconnecting")
                    self._reconnect()
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                self.logger.error(f"Connection lost: {e}")
                self._reconnect()
                continue

            if not data:
                self.logger.warning("Connection closed by server")
                self._reconnect()
                continue

            # Reset heartbeat counter on any data
            self.heartbeat_counter = 0

            self.logger.debug("Received %d bytes: %s", len(data), data.hex())

            # Stream preprocessing (none needed)
            data = self.preprocess_stream(data)

            self.buffer.extend(data)

            # Extract complete packets from buffer
            for packet in self.extract_packets():
                # Decode (no encryption)
                decoded = self.decode_packet(packet)

                # Extract individual messages from the packet
                for message in self.extract_messages(decoded):
                    message_type = self.get_message_type(message)
                    self.handle_message(message, message_type)

                    parsed = self.message_parser.parse_message(
                        timestamp=datetime.now(timezone.utc),
                        source_ip=self.HOST_IP,
                        data=message,
                        message_type=message_type
                    )
                    self.logger.debug("Parsed message: %s", parsed)
                    yield parsed

    def heartbeat(self):
        """Send a 2-byte heartbeat (0x0000) to keep the connection alive."""
        if self.socket:
            try:
                self.socket.sendall(self.HEARTBEAT)
                self.logger.debug("Heartbeat sent")
            except OSError:
                pass

    def preprocess_stream(self, data: bytes) -> bytes:
        """No stream-level transformation needed."""
        return data

    def extract_packets(self) -> Iterable[bytes]:
        """
        Extract complete framed packets from the internal buffer.

        Packet format:
          [2-byte big-endian length] [N-byte payload] [2-byte remaining] [remaining bytes]

        If length == 0, read another 2 bytes for extended length.
        If length > MAX_PACKET_SIZE, discard and log error.
        """
        while len(self.buffer) >= 2:
            # Peek at length
            length = struct.unpack("!H", self.buffer[:2])[0]
            offset = 2

            if length == 0:
                # Extended length: read next 2 bytes
                if len(self.buffer) < 4:
                    break
                length = struct.unpack("!H", self.buffer[2:4])[0]
                offset = 4

            if length > self.MAX_PACKET_SIZE:
                self.logger.error(f"Packet too large ({length} bytes), discarding")
                self.buffer.clear()
                self._reconnect()
                return

            # Need payload + 2-byte remaining field
            if len(self.buffer) < offset + length + 2:
                break

            # Read payload
            payload = self.buffer[offset:offset + length]
            offset += length

            # Read remaining data length
            remaining = struct.unpack("!H", self.buffer[offset:offset + 2])[0]
            offset += 2

            if remaining > 0:
                if len(self.buffer) < offset + remaining:
                    break
                # Include remaining data as part of the packet (though not used)
                # We'll yield the entire packet from length field to end
                packet_end = offset + remaining
            else:
                packet_end = offset

            # Yield the complete packet (including framing)
            packet = self.buffer[:packet_end]
            del self.buffer[:packet_end]
            yield packet

    def decode_packet(self, packet: bytes) -> bytes:
        """No decryption; return as-is."""
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        """
        Extract the actual command payload from a framed packet.

        The packet includes the length field, payload, remaining length,
        and remaining data. We return only the payload as the message.
        """
        # Parse framing again to extract payload
        if len(packet) < 2:
            return
        length = struct.unpack("!H", packet[:2])[0]
        offset = 2
        if length == 0:
            if len(packet) < 4:
                return
            length = struct.unpack("!H", packet[2:4])[0]
            offset = 4

        if len(packet) < offset + length + 2:
            return
        payload = packet[offset:offset + length]
        yield payload

    def get_message_type(self, message: bytes) -> MessageType:
        """
        Classify the message based on the command structure.

        - If first 4 bytes (duration) == 0 and method ID is 0xFE or 0xFF -> COMMAND
        - Otherwise -> ATTACK
        - HEARTBEAT and ACK are not sent by the server in this protocol.
        """
        if len(message) < 5:
            return MessageType.COMMAND

        duration = struct.unpack("!I", message[:4])[0]
        method_id = message[4]  # signed byte

        if duration == 0:
            # Control commands: 0xFE (stop attacks) and 0xFF (toggle scanner)
            if method_id in (0xFE, 0xFF):
                return MessageType.COMMAND
            # Other zero-duration commands are still attack-related? Treat as ATTACK
            return MessageType.ATTACK

        # Non-zero duration indicates an attack command
        return MessageType.ATTACK

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        Protocol-specific handling.

        The bot does not send ACKs or responses for received commands.
        No action is needed.
        """
        pass

    def _reconnect(self):
        """Close current socket and re-establish connection."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        self.buffer.clear()
        self.heartbeat_counter = 0
        self.connect()
