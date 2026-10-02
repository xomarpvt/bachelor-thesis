import socket
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    HOST_IP = "92.112.127.220"
    PORT = 21242

    IDENTIFICATION = b'\x03\x04'
    HEARTBEAT = b'\x00\x00'

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 10
    MAX_PAYLOAD = 0x400

    SIMULATED_LOCAL_IP = (192, 168, 1, 100)
    DEFAULT_PASSWORD = b"botnet"

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)
        self.heartbeat_counter = 0

    def connect(self):
        self.logger.info(f"Connecting to {self.HOST_IP}:{self.PORT}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.HOST_IP, self.PORT))

        self.logger.info("Connected")

        self.socket.sendall(self.IDENTIFICATION)
        self.logger.debug("Sent identification bytes: %s", self.IDENTIFICATION.hex())

        self.authentication()

        self.logger.info("Authenticated")

    def sniff(self):
        self.logger.info("Listening ...")

        while True:
            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                data = b""

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
                            source_ip=self.HOST_IP,
                            data=message,
                            message_type=message_type
                        )

                        self.logger.debug("Parsed: %s", parsed_message)
                        yield parsed_message

            self.heartbeat_counter += 1
            if self.heartbeat_counter % 6 == 0:
                self.heartbeat()

    def authentication(self) -> None:
        if self.socket:
            local_ip_bytes = bytes(self.SIMULATED_LOCAL_IP)
            self.socket.sendall(local_ip_bytes)

            password = self.DEFAULT_PASSWORD
            password_len = len(password)
            self.socket.sendall(bytes([password_len]))

            if password_len > 0:
                self.socket.sendall(password)

    def heartbeat(self) -> None:
        if self.socket:
            self.socket.sendall(self.HEARTBEAT)

    def preprocess_stream(self, data: bytes) -> bytes:
        return data

    def extract_packets(self) -> Iterable[bytes]:
        while len(self.buffer) >= 2:
            cmd_type = (self.buffer[0] << 8) | self.buffer[1]

            if cmd_type == 0:
                if len(self.buffer) >= 4:
                    packet = bytes(self.buffer[:4])
                    del self.buffer[:4]
                    yield packet
                else:
                    return
            else:
                if len(self.buffer) >= 4:
                    payload_len = (self.buffer[2] << 8) | self.buffer[3]
                    if payload_len > self.MAX_PAYLOAD:
                        del self.buffer[:4]
                        continue
                    total_len = 4 + payload_len
                    if len(self.buffer) >= total_len:
                        packet = bytes(self.buffer[:total_len])
                        del self.buffer[:total_len]
                        yield packet
                    else:
                        return
                else:
                    return

    def decode_packet(self, packet: bytes) -> bytes:
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        if len(message) >= 2:
            cmd_type = (message[0] << 8) | message[1]
            if cmd_type == 0:
                return MessageType.ACK
        return MessageType.ATTACK

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        pass
