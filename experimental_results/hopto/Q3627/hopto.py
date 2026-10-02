import select
import socket
import struct
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    C2_DOMAIN = "osfjkqoiw382r552q.hopto.org"
    C2_PORT = 51

    PROTOCOL_HEADER = b'\x00\x00\x00\x01'
    AUTH_BYTE = b'\x42'
    HEARTBEAT = b'\x00\x00'

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 10
    MAX_PACKET_LENGTH = 0x400

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0
        self.c2_password = b''
        self.c2_ip: Optional[str] = None

    def connect(self):
        self.c2_ip = self._resolve_c2_address()

        self.logger.info(f"Connecting to {self.c2_ip}:{self.C2_PORT}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.c2_ip, self.C2_PORT))

        self.logger.info("Connected")

        self._authenticate()

        self.logger.info("Authenticated")

    def _resolve_c2_address(self) -> str:
        try:
            addr_info = socket.getaddrinfo(
                self.C2_DOMAIN, self.C2_PORT, socket.AF_INET, socket.SOCK_STREAM
            )
            if addr_info:
                return addr_info[0][4][0]
        except Exception as e:
            self.logger.warning(f"DNS resolution failed: {e}")
        return "127.0.0.1"

    def _authenticate(self) -> None:
        self.socket.sendall(self.PROTOCOL_HEADER)

        pwd_len = len(self.c2_password)
        self.socket.sendall(struct.pack('B', pwd_len))

        if pwd_len > 0:
            self.socket.sendall(self.c2_password)

        self.socket.sendall(self.AUTH_BYTE)

    def sniff(self):
        self.logger.info("Listening ...")

        while True:
            try:
                readable, _, _ = select.select(
                    [self.socket], [], [], self.SOCKET_TIMEOUT
                )
            except Exception as e:
                self.logger.error(f"Select error: {e}")
                break

            if readable:
                try:
                    data = self.socket.recv(self.BUFFER_SIZE)
                except socket.timeout:
                    data = b''
                except Exception as e:
                    self.logger.error(f"Receive error: {e}")
                    break

                if not data:
                    self.logger.info("Connection closed by server")
                    break

                self.logger.debug(
                    "Received %d bytes: %s", len(data), data.hex()
                )
                self.buffer.extend(data)

                for packet in self.extract_packets():
                    packet = self.decode_packet(packet)
                    for message in self.extract_messages(packet):
                        message_type = self.get_message_type(message)
                        self.handle_message(message, message_type)

                        parsed_message = self.message_parser.parse_message(
                            timestamp=datetime.now(timezone.utc),
                            source_ip=self.c2_ip or "0.0.0.0",
                            data=message,
                            message_type=message_type
                        )

                        self.logger.debug("Parsed: %s", parsed_message)
                        yield parsed_message
            else:
                self.heartbeat_counter += 1
                if self.heartbeat_counter % 4 == 0:
                    self._send_heartbeat()

    def _has_complete_packet(self) -> bool:
        if len(self.buffer) < 2:
            return False

        first_len = struct.unpack('!H', self.buffer[:2])[0]

        if first_len > self.MAX_PACKET_LENGTH:
            return False

        if len(self.buffer) < 2 + first_len + 2:
            return False

        second_len = struct.unpack(
            '!H', self.buffer[2 + first_len:2 + first_len + 2]
        )[0]

        return len(self.buffer) >= 2 + first_len + 2 + second_len

    def _extract_packet(self) -> Optional[bytes]:
        if len(self.buffer) < 2:
            return None

        first_len = struct.unpack('!H', self.buffer[:2])[0]

        if first_len > self.MAX_PACKET_LENGTH:
            self.logger.warning(f"Invalid packet length: {first_len}")
            self.buffer.clear()
            return None

        if len(self.buffer) < 2 + first_len + 2:
            return None

        second_len = struct.unpack(
            '!H', self.buffer[2 + first_len:2 + first_len + 2]
        )[0]

        if len(self.buffer) < 2 + first_len + 2 + second_len:
            return None

        packet = bytes(self.buffer[:2 + first_len + 2 + second_len])
        self.buffer = self.buffer[2 + first_len + 2 + second_len:]

        return packet

    def extract_packets(self) -> Iterable[bytes]:
        while self._has_complete_packet():
            packet = self._extract_packet()
            if packet is not None:
                yield packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        if len(packet) < 2:
            return

        first_len = struct.unpack('!H', packet[:2])[0]

        if first_len == 0:
            yield packet
            return

        if len(packet) < 2 + first_len + 2:
            return

        second_len = struct.unpack(
            '!H', packet[2 + first_len:2 + first_len + 2]
        )[0]

        second_data = packet[2 + first_len + 2:2 + first_len + 2 + second_len]

        if second_data:
            yield second_data

    def get_message_type(self, message: bytes) -> MessageType:
        if len(message) >= 2:
            first_len = struct.unpack('!H', message[:2])[0]
            if first_len == 0:
                return MessageType.HEARTBEAT

        if len(message) >= 5:
            method_id = message[4]
            if method_id == 0xFF or method_id == 0xFE:
                return MessageType.COMMAND
            return MessageType.ATTACK

        return MessageType.COMMAND

    def _send_heartbeat(self) -> None:
        try:
            self.socket.sendall(self.HEARTBEAT)
        except Exception as e:
            self.logger.error(f"Heartbeat send failed: {e}")
