import socket
import struct
import time
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    HOST_IP = "62.60.159.184"
    PORT = 53574

    PROTOCOL_VERSION = struct.pack("<I", 0x00000001)
    LOGIN_FLAG = bytes([0x03])
    ARCH_BYTE = bytes([0x78])

    HEARTBEAT = bytes([0x00, 0x00])

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 30
    MAX_PACKET_SIZE = 0x2000
    HEARTBEAT_MAX = 119

    BACKOFF_INITIAL = 1
    BACKOFF_CAP = 60

    PASSWORD = b"deepsorrow"

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0
        self.backoff_delay = self.BACKOFF_INITIAL
        self.connected = False
        self._last_recv_was_timeout = False

    def connect(self):
        if self.backoff_delay > self.BACKOFF_INITIAL:
            self.logger.info("Backoff delay: %ds", self.backoff_delay)
            time.sleep(self.backoff_delay)

        self.logger.info("Connecting to %s:%d", self.HOST_IP, self.PORT)

        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass

        self.socket.connect((self.HOST_IP, self.PORT))
        self.connected = True

        self.logger.info("Connected")

        self.authentication()

        self.logger.info("Logged in")

    def sniff(self):
        self.logger.info("Listening ...")

        while True:
            if not self.connected or self.socket is None:
                try:
                    self.connect()
                except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
                    self.logger.warning("Connection failed: %s", e)
                    self.backoff_delay = min(self.backoff_delay * 2, self.BACKOFF_CAP)
                    continue

            try:
                data = self.socket.recv(self.BUFFER_SIZE)
                self._last_recv_was_timeout = False
            except socket.timeout:
                data = b""
                self._last_recv_was_timeout = True
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                self.logger.warning("Connection lost: %s", e)
                self.connected = False
                if self.socket:
                    try:
                        self.socket.close()
                    except OSError:
                        pass
                    self.socket = None
                self.backoff_delay = min(self.backoff_delay * 2, self.BACKOFF_CAP)
                continue

            if data:
                self.heartbeat_counter = 0
                self.logger.debug("Received %d bytes: %s", len(data), data.hex())

                data = self.preprocess_stream(data)
                self.buffer.extend(data)

                for packet in self.extract_packets():
                    packet = self.decode_packet(packet)

                    for message in self.extract_messages(packet):
                        message_type = self.get_message_type(message)
                        self.handle_message(message, message_type)

                        parsed_message = self.message_parser.parse_message(
                            timestamp=datetime.now(timezone.utc),
                            source_ip=self.HOST_IP,
                            data=message,
                            message_type=message_type
                        )

                        self.logger.debug("Parsed: %s", parsed_message)
                        yield parsed_message

            self.heartbeat()

    def authentication(self) -> None:
        if not self.socket:
            return

        self.socket.sendall(self.PROTOCOL_VERSION)
        self.socket.sendall(struct.pack("B", len(self.PASSWORD)))
        if len(self.PASSWORD) > 0:
            self.socket.sendall(self.PASSWORD)
        self.socket.sendall(self.LOGIN_FLAG)
        self.socket.sendall(self.ARCH_BYTE)

    def heartbeat(self) -> None:
        if self.socket and self.connected and self._last_recv_was_timeout:
            self.socket.sendall(self.HEARTBEAT)
            self.heartbeat_counter += 1

            if self.heartbeat_counter > self.HEARTBEAT_MAX:
                self.logger.warning("Heartbeat timeout exceeded, reconnecting")
                self.heartbeat_counter = 0
                self.connected = False
                if self.socket:
                    try:
                        self.socket.close()
                    except OSError:
                        pass
                    self.socket = None
                self.backoff_delay = self.BACKOFF_INITIAL

    def extract_packets(self) -> Iterable[bytes]:
        while len(self.buffer) >= 2:
            length1 = struct.unpack("!H", self.buffer[0:2])[0]

            if length1 == 0:
                if len(self.buffer) >= 4:
                    yield self.buffer[0:4]
                    self.buffer = self.buffer[4:]
                else:
                    break
                continue

            if length1 > self.MAX_PACKET_SIZE:
                self.logger.error("Packet length %d exceeds maximum %d", length1, self.MAX_PACKET_SIZE)
                self.buffer = bytearray()
                break

            min_needed = 2 + length1 + 2
            if len(self.buffer) < min_needed:
                break

            length2 = struct.unpack("!H", self.buffer[2 + length1:2 + length1 + 2])[0]

            if length2 > 0:
                if len(self.buffer) < min_needed + length2:
                    break
                payload = self.buffer[2 + length1 + 2:2 + length1 + 2 + length2]
                consumed = 2 + length1 + 2 + length2
            else:
                payload = self.buffer[2:2 + length1]
                consumed = min_needed

            yield payload
            self.buffer = self.buffer[consumed:]

    def get_message_type(self, message: bytes) -> MessageType:
        if len(message) == 4 and message == b'\x00\x00\x00\x00':
            return MessageType.HEARTBEAT

        if len(message) >= 6:
            method_id = message[4]
            target_count = message[5]

            if method_id in (0xFF, 0xFE, 0xFD):
                return MessageType.COMMAND

            if 0x00 <= method_id <= 0x1A and target_count > 0:
                return MessageType.ATTACK

        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        pass
