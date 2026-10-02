import socket
import struct
import time
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):
    """
    Gafgyt/Mirai C2 communication module.

    Implements the botnet's TCP-based transport, XOR-obfuscated string table,
    authentication handshake, length-prefixed command framing, and periodic
    heartbeat keepalive.
    """

    # C2 endpoint (domain resolved at connect time)
    HOST_NAME = "osfjkqoiw382r552q.hopto.org"
    HOST_IP = None  # resolved from HOST_NAME
    PORT = 69  # 0x0045

    # Authentication payload
    HANDSHAKE = b'\x00\x00\x00\x01'  # 4-byte magic header
    PASSWORD = b''  # no password (argv[1] omitted)
    AUTH_BYTE = b'B'  # first byte of table entry 3 ("Bruh why again")

    # Heartbeat payload (2 zero bytes)
    HEARTBEAT = b'\x00\x00'

    # Protocol constants
    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 10  # select() timeout in seconds
    HEARTBEAT_INTERVAL = 4  # send heartbeat every 4th timeout (~40s)
    MAX_PAYLOAD_SIZE = 1024

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.heartbeat_counter = 0
        self.message_parser = MessageParser(ip_lookup)

    # ------------------------------------------------------------------
    # Connection & authentication
    # ------------------------------------------------------------------

    def connect(self):
        """Resolve C2 domain, create TCP socket, and perform login handshake."""
        # Resolve domain if needed
        if self.HOST_IP is None:
            self.logger.info("Resolving C2 domain: %s", self.HOST_NAME)
            self.HOST_IP = socket.gethostbyname(self.HOST_NAME)
            self.logger.info("Resolved to %s", self.HOST_IP)

        self.logger.info("Connecting to %s:%d", self.HOST_IP, self.PORT)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.HOST_IP, self.PORT))

        self.logger.info("Connected, sending authentication")
        self._send_authentication()
        self.logger.info("Authentication sent, session established")

    def _send_authentication(self):
        """Send the login payload as defined by the protocol."""
        # Magic header (4 bytes)
        self.socket.sendall(self.HANDSHAKE)

        # Password length (1 byte)
        pass_len = len(self.PASSWORD)
        self.socket.sendall(struct.pack('!B', pass_len))

        # Password (if any)
        if pass_len > 0:
            self.socket.sendall(self.PASSWORD)

        # Auth byte (1 byte from table entry 3)
        self.socket.sendall(self.AUTH_BYTE)

    # ------------------------------------------------------------------
    # Main receive loop
    # ------------------------------------------------------------------

    def sniff(self):
        """
        Listen for C2 commands indefinitely.

        Handles server heartbeats, command framing, and periodic client
        heartbeats. Yields parsed message dicts.
        """
        self.logger.info("Entering command receive loop")

        while True:
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                # No data within SOCKET_TIMEOUT – handle heartbeat
                self.heartbeat_counter += 1
                if self.heartbeat_counter % self.HEARTBEAT_INTERVAL == 0:
                    self._send_heartbeat()
                continue
            except (socket.error, OSError) as exc:
                self.logger.error("Socket error: %s", exc)
                raise  # Let caller reconnect

            if not data:
                self.logger.warning("Connection closed by server")
                raise ConnectionError("Server closed connection")

            self.logger.debug("Received %d bytes: %s", len(data), data.hex())

            # No stream-level preprocessing needed
            self.buffer.extend(data)

            # Extract complete packets from buffer
            for packet in self._extract_packets():
                # No decryption needed (plaintext)
                # Each packet is a single message
                message = packet
                message_type = self._get_message_type(message)
                self._handle_message(message, message_type)

                parsed = self.message_parser.parse_message(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=self.HOST_IP,
                    data=message,
                    message_type=message_type,
                )
                self.logger.debug("Parsed message: %s", parsed)
                yield parsed

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def _send_heartbeat(self):
        """Send a 2-byte zero heartbeat to keep the connection alive."""
        if self.socket:
            try:
                self.socket.sendall(self.HEARTBEAT)
                self.logger.debug("Heartbeat sent")
            except (socket.error, OSError) as exc:
                self.logger.error("Heartbeat send failed: %s", exc)
                raise

    # ------------------------------------------------------------------
    # Packet framing (length-prefixed protocol)
    # ------------------------------------------------------------------

    def _extract_packets(self) -> Iterable[bytes]:
        """
        Parse the receive buffer for complete C2 command packets.

        Protocol framing:
          [2 bytes: length N (big-endian)]
          [N bytes: first payload (discarded)]
          [2 bytes: length M (big-endian)]
          [M bytes: actual command payload]

        Special case: if first length is 0, it's a server heartbeat;
        read and discard the next 2 bytes, then continue.
        """
        while len(self.buffer) >= 2:
            # Read first length prefix
            first_len = struct.unpack('!H', self.buffer[:2])[0]

            if first_len == 0:
                # Server heartbeat – discard 2 bytes of length + 2 bytes of data
                if len(self.buffer) < 4:
                    break
                self.logger.debug("Server heartbeat received")
                self.buffer = self.buffer[4:]  # discard 4 bytes
                continue

            if first_len > self.MAX_PAYLOAD_SIZE:
                self.logger.warning(
                    "Invalid packet length %d (> %d), closing connection",
                    first_len, self.MAX_PAYLOAD_SIZE,
                )
                self.buffer.clear()
                raise ConnectionError("Protocol violation: oversized packet")

            # Need first payload + second length prefix
            needed = 2 + first_len + 2
            if len(self.buffer) < needed:
                break

            # Discard first payload (skip length + data)
            offset = 2 + first_len

            # Read second length prefix
            second_len = struct.unpack('!H', self.buffer[offset:offset+2])[0]
            offset += 2

            if second_len > self.MAX_PAYLOAD_SIZE:
                self.logger.warning(
                    "Invalid second packet length %d, closing connection",
                    second_len,
                )
                self.buffer.clear()
                raise ConnectionError("Protocol violation: oversized second packet")

            # Need second payload
            total_needed = offset + second_len
            if len(self.buffer) < total_needed:
                break

            # Extract actual command payload
            command_payload = bytes(self.buffer[offset:offset+second_len])

            # Remove consumed bytes from buffer
            self.buffer = self.buffer[total_needed:]

            self.logger.debug(
                "Extracted command packet: len=%d, data=%s",
                second_len, command_payload.hex(),
            )
            yield command_payload

    # ------------------------------------------------------------------
    # Message classification
    # ------------------------------------------------------------------

    def _get_message_type(self, message: bytes) -> MessageType:
        """
        Determine message type from the command payload.

        The first 4 bytes are target IP (big-endian), byte 4 is command ID.
        Special IDs: 0xFF (KILL) and 0xFE (UPDATE) are COMMAND.
        All other IDs (0x00–0x2A) are ATTACK.
        """
        if len(message) < 5:
            # Too short to be a valid attack command – treat as COMMAND
            return MessageType.COMMAND

        command_id = message[4]
        if command_id in (0xFF, 0xFE):
            return MessageType.COMMAND
        else:
            return MessageType.ATTACK

    # ------------------------------------------------------------------
    # Protocol-specific message handling
    # ------------------------------------------------------------------

    def _handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        Handle protocol-level actions for a received message.

        The Gafgyt/Mirai protocol does not require any response to commands
        or heartbeats. This method is intentionally empty.
        """
        pass

    # ------------------------------------------------------------------
    # Override template methods (not used, but kept for compatibility)
    # ------------------------------------------------------------------

    def authentication(self) -> None:
        """Not used – authentication is performed in connect()."""
        pass

    def heartbeat(self) -> None:
        """Not used – heartbeat is handled internally via _send_heartbeat()."""
        pass

    def preprocess_stream(self, data: bytes) -> bytes:
        return data

    def extract_packets(self) -> Iterable[bytes]:
        return self._extract_packets()

    def decode_packet(self, packet: bytes) -> bytes:
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        return self._get_message_type(message)

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        self._handle_message(message, message_type)
