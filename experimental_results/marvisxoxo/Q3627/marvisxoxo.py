import socket
import struct
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    C2_HOSTNAMES = [
        "marvisxoxo.st",
        "valid.marvisxoxo.st",
        "tls.marvisxoxo.st"
    ]
    HOST_IP = "127.0.0.1"
    PORT = 53537  # 0xd121

    AUTH_PREFIX = bytes([
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x03, 0x02, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01
    ])

    XOR_KEY = 0xED
    HEARTBEAT = bytes([0x00, 0x00])

    BUFFER_SIZE = 1024
    SOCKET_TIMEOUT = 15
    HEARTBEAT_ITERATIONS = 4  # 4 * 15s = 60s

    DEFAULT_PASSWORD = b"gafgyt"
    CPU_CORES = 1

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0
        self.connected = False
        self.c2_ip = self.HOST_IP

    def connect(self):
        self.c2_ip = self._resolve_c2_ip()

        self.logger.info(f"Connecting to {self.c2_ip}:{self.PORT}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.c2_ip, self.PORT))

        self.logger.info("Connected")

        self.authentication()

        self.connected = True
        self.logger.info("Logged in")

    def _resolve_c2_ip(self) -> str:
        for hostname in self.C2_HOSTNAMES:
            try:
                ip = socket.gethostbyname(hostname)
                self.logger.info(f"Resolved {hostname} to {ip}")
                return ip
            except socket.gaierror:
                continue

        self.logger.warning("DNS resolution failed, using fallback IP: %s", self.HOST_IP)
        return self.HOST_IP

    def sniff(self):
        self.logger.info("Listening ...")

        while True:
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                data = b""
                self.heartbeat_counter += 1

            if data:
                self.logger.debug("Received %d bytes: %s", len(data), data.hex())

                self.buffer.extend(data)

                for packet in self.extract_packets():
                    packet = self.decode_packet(packet)

                    for message in self.extract_messages(packet):
                        message_type = self.get_message_type(message)

                        self.handle_message(message, message_type)

                        parsed_message = self.message_parser.parse_message(
                            timestamp=datetime.now(timezone.utc),
                            source_ip=self.c2_ip,
                            data=message,
                            message_type=message_type
                        )

                        self.logger.debug("Parsed: %s", parsed_message)

                        yield parsed_message

            self._send_heartbeat_if_due()

    def _send_heartbeat_if_due(self):
        if self.connected and self.heartbeat_counter >= self.HEARTBEAT_ITERATIONS:
            self.heartbeat()
            self.heartbeat_counter = 0

    def authentication(self) -> None:
        if self.socket:
            auth_packet = self._build_authentication_packet()
            self.logger.info("Sending authentication packet (%d bytes)", len(auth_packet))
            self.socket.sendall(auth_packet)

    def _build_authentication_packet(self) -> bytes:
        password = self.DEFAULT_PASSWORD
        core_count = self.CPU_CORES

        payload = bytearray(password)
        payload.append(core_count)

        encrypted_payload = bytearray(len(payload))
        for i in range(len(payload)):
            encrypted_payload[i] = payload[i] ^ self.XOR_KEY

        checksum = self._internet_checksum(bytes(encrypted_payload))

        packet = bytearray(self.AUTH_PREFIX)
        packet.extend(encrypted_payload)
        packet.extend(struct.pack('>H', checksum))

        return bytes(packet)

    def _internet_checksum(self, data: bytes) -> int:
        if len(data) % 2 != 0:
            data = data + b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF

    def heartbeat(self) -> None:
        if self.socket and self.connected:
            self.logger.debug("Sending heartbeat")
            self.socket.sendall(self.HEARTBEAT)

    def preprocess_stream(self, data: bytes) -> bytes:
        return data

    def extract_packets(self) -> Iterable[bytes]:
        if len(self.buffer) > 0:
            packet = bytes(self.buffer)
            self.buffer.clear()
            yield packet

    def decode_packet(self, packet: bytes) -> bytes:
        decrypted = bytearray(len(packet))
        for i in range(len(packet)):
            decrypted[i] = packet[i] ^ self.XOR_KEY
        return bytes(decrypted)

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        if len(message) < 2:
            return MessageType.COMMAND

        if message == b'\x00\x00':
            return MessageType.HEARTBEAT

        if message == b'\x00':
            return MessageType.ACK

        if len(message) >= 6:
            duration = struct.unpack('>I', message[0:4])[0]
            method_id = message[4]
            target_count = message[5]

            if 1 <= method_id <= 8 and target_count > 0:
                if len(message) >= 6 + target_count * 5:
                    return MessageType.ATTACK

        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        pass
