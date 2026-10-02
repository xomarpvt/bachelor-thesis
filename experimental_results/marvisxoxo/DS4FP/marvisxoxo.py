import socket
import select
import struct
import random
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):
    """
    Gafgyt/Qbot botnet C2 communication module (sample 'marvisxoxo').

    Implements the exact transport layer: non-blocking connect, authentication,
    select-driven command loop, heartbeat, and XOR-based encryption.
    """

    # ------------------------------------------------------------------ #
    #  C2 Endpoint (configurable for defensive simulation)               #
    # ------------------------------------------------------------------ #
    HOST_NAME = "marvisxoxo.st"          # Primary C2 domain (for reference)
    HOST_IP = "127.0.0.12"              # Simulated C2 IP address
    PORT = 19876                         # Will be overwritten by random selection

    # ------------------------------------------------------------------ #
    #  Protocol Constants                                                #
    # ------------------------------------------------------------------ #
    # 11 port candidates (little-endian uint16 values from binary)
    C2_PORTS = [
        19876, 60764, 27603, 27776, 29502,
        1207,  26608, 7574,  876,   57536,
        7193
    ]

    # Client authentication header (19 bytes, plaintext)
    AUTH_HEADER_CLIENT = bytes([
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
        0x03, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x05, 0x04, 0x03, 0x02, 0x01
    ])

    # Server authentication acknowledgment header (18 bytes, after XOR)
    AUTH_HEADER_SERVER = bytes([
        0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01, 0x03,
        0x02, 0x0E, 0x0A, 0x0D, 0x0E, 0x03, 0x02, 0x00,
        0x0A, 0x0B
    ])

    XOR_KEY = 0xED
    HEARTBEAT = bytes([0x00, 0x00])          # 2-byte heartbeat payload
    SELECT_TIMEOUT = 10                      # seconds
    HEARTBEAT_INTERVAL = 6                   # every 6th timeout
    BUFFER_SIZE = 1024                       # recv buffer size
    CONNECT_TIMEOUT = 10                     # seconds for initial connect

    # Simulated victim attributes (no real system discovery)
    SIMULATED_CPU_COUNT = 4                  # typical IoT device
    DEFAULT_PASSWORD = "h"                   # fallback when no password provided

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self._heartbeat_counter = 0
        self._password = self.DEFAULT_PASSWORD

    # ------------------------------------------------------------------ #
    #  Public interface (BotNetInterface)                                #
    # ------------------------------------------------------------------ #

    def connect(self):
        """
        Establish a TCP connection to the C2 server and perform authentication.

        Steps:
        1. Randomly select a C2 port from the hardcoded list.
        2. Create a non-blocking socket and connect.
        3. Wait for connection using select() with a 10-second timeout.
        4. On success, send the authentication packet.
        """
        # Select random port
        port = random.choice(self.C2_PORTS)
        self.logger.info(
            "Connecting to %s:%d (selected from port table)",
            self.HOST_IP, port
        )

        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)

        # Initiate non-blocking connect
        try:
            self.socket.connect((self.HOST_IP, port))
        except BlockingIOError:
            pass  # Expected for non-blocking sockets

        # Wait for connection using select
        _, writable, _ = select.select(
            [], [self.socket], [], self.CONNECT_TIMEOUT
        )

        if not writable:
            self.logger.error("Connection timed out")
            self.socket.close()
            self.socket = None
            raise ConnectionError("C2 connection timeout")

        # Check socket error
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            self.logger.error("Connection failed with error %d", err)
            self.socket.close()
            self.socket = None
            raise ConnectionError(f"SO_ERROR: {err}")

        # Connection successful – switch to blocking mode for simplicity
        self.socket.setblocking(True)
        self.socket.settimeout(self.SELECT_TIMEOUT)

        self.logger.info("Connected to C2 server")
        self._send_authentication()
        self.logger.info("Authentication packet sent")

    def sniff(self):
        """
        Run the C2 command loop indefinitely.

        Uses select() with a 10-second timeout. On timeout, sends heartbeat
        every 6th iteration. On data arrival, XOR-decrypts and classifies
        the message. Yields parsed messages for further processing.
        """
        self.logger.info("Entering C2 command loop")

        while True:
            # Prepare select sets
            readable, _, _ = select.select(
                [self.socket], [], [], self.SELECT_TIMEOUT
            )

            if not readable:
                # Timeout – handle heartbeat
                self._heartbeat_counter += 1
                if self._heartbeat_counter % self.HEARTBEAT_INTERVAL == 0:
                    self.heartbeat()
                continue

            # Data available on socket
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                continue
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                self.logger.warning("Connection lost: %s", e)
                break

            if not data:
                self.logger.warning("Connection closed by server")
                break

            self.logger.debug("Received %d bytes: %s", len(data), data.hex())

            # Process the received data through the template pipeline
            data = self.preprocess_stream(data)
            self.buffer.extend(data)

            for packet in self.extract_packets():
                decoded = self.decode_packet(packet)
                for message in self.extract_messages(decoded):
                    message_type = self.get_message_type(message)
                    self.handle_message(message, message_type)

                    parsed = self.message_parser.parse_message(
                        timestamp=datetime.now(timezone.utc),
                        source_ip=self.HOST_IP,
                        data=message,
                        message_type=message_type
                    )
                    self.logger.debug("Parsed: %s", parsed)
                    yield parsed

    # ------------------------------------------------------------------ #
    #  Protocol-specific overrides                                       #
    # ------------------------------------------------------------------ #

    def authentication(self) -> None:
        """
        Not used – authentication is performed inside connect().
        """
        pass

    def heartbeat(self) -> None:
        """
        Send a 2-byte heartbeat (0x00 0x00) to keep the connection alive.
        """
        if self.socket:
            try:
                self.socket.sendall(self.HEARTBEAT)
                self.logger.debug("Heartbeat sent")
            except OSError as e:
                self.logger.warning("Failed to send heartbeat: %s", e)

    def preprocess_stream(self, data: bytes) -> bytes:
        """
        No stream-level transformation required.
        """
        return data

    def extract_packets(self) -> Iterable[bytes]:
        """
        Each recv() yields exactly one complete packet.
        Yield the accumulated buffer and clear it.
        """
        if self.buffer:
            packet = bytes(self.buffer)
            self.buffer.clear()
            yield packet

    def decode_packet(self, packet: bytes) -> bytes:
        """
        XOR-decrypt the packet with key 0xED.
        """
        return bytes(b ^ self.XOR_KEY for b in packet)

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        """
        A decoded packet is a single message.
        """
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        """
        Classify the message based on the server authentication header.

        - If the first 18 bytes match AUTH_HEADER_SERVER → ACK
        - Otherwise → ATTACK (commands are the only other type)
        """
        if len(message) >= 18 and message[:18] == self.AUTH_HEADER_SERVER:
            return MessageType.ACK
        return MessageType.ATTACK

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        No explicit response is required for any message type.
        The protocol does not define ACKs for commands.
        """
        pass

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                  #
    # ------------------------------------------------------------------ #

    def _send_authentication(self) -> None:
        """
        Build and send the authentication packet as defined in the spec.

        Packet structure:
        - 19 bytes: client auth header (plaintext)
        - 1 byte: password length
        - N bytes: password (XOR'd with 0xED)
        - 1 byte: CPU count (XOR'd)
        - 2 bytes: IP-style checksum (over XOR'd password + CPU count, little-endian)
        """
        password = self._password.encode() if isinstance(self._password, str) else self._password
        pwd_len = len(password)
        cpu_count = self.SIMULATED_CPU_COUNT

        # Build payload: password + CPU count (both will be XOR'd)
        payload = bytearray(password)
        payload.append(cpu_count)

        # XOR encrypt the payload
        xor_payload = bytes(b ^ self.XOR_KEY for b in payload)

        # Compute IP checksum over the XOR'd payload
        checksum = self._ip_checksum(xor_payload)

        # Assemble the full packet
        packet = bytearray()
        packet.extend(self.AUTH_HEADER_CLIENT)
        packet.append(pwd_len)
        packet.extend(xor_payload)
        packet.extend(struct.pack('<H', checksum))  # little-endian uint16

        self.logger.debug(
            "Sending auth packet (%d bytes): %s",
            len(packet), packet.hex()
        )
        self.socket.sendall(bytes(packet))

    @staticmethod
    def _ip_checksum(data: bytes) -> int:
        """
        Compute the 16-bit ones' complement checksum (IP-style).

        The data is treated as a sequence of 16-bit little-endian words.
        If an odd byte remains, it is zero-padded.
        """
        if len(data) % 2 != 0:
            data += b'\x00'  # pad to even length

        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] | (data[i+1] << 8)) & 0xFFFF
            total += word

        # Fold 32-bit sum to 16 bits
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)

        return (~total) & 0xFFFF
