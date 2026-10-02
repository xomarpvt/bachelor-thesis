import socket
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..base import BotnetInterface
from .parser import MessageParser, MessageType


class Botnet(BotnetInterface):

    HOST_NAME = ""  # DNS Hostname
    HOST_IP = "127.0.0.12"  # IP Address
    PORT = 8888

    HANDSHAKE = b'ciao'
    ACK = bytes([0x00, 0x00])
    HEARTBEAT = bytes([0x00, 0x00])

    BUFFER_SIZE = 8192
    SOCKET_TIMEOUT = 60

    def __init__(self, logger, ip_lookup):
        super().__init__(logger, ip_lookup)
        self.socket: Optional[socket.socket] = None
        self.buffer = bytearray()
        self.message_parser = MessageParser(ip_lookup)

    def connect(self):
        self.logger.info(f"Connecting to {self.HOST_IP}:{self.PORT}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.SOCKET_TIMEOUT)
        self.socket.connect((self.HOST_IP, self.PORT))

        self.logger.info(f"Connected")

        self.authentication()

        self.logger.info("Logged in")

    def sniff(self):
        self.logger.info("Listening ...")

        while True:

            try:
                data = self.socket.recv(self.BUFFER_SIZE)
            except socket.timeout:
                data = b""

            if data:

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
        """
        Perform the initial protocol authentication.

        Override to implement the protocol-specific login or handshake
        sequence required before normal message exchange.
        """
        if self.socket:
            self.socket.sendall(self.HANDSHAKE)

    def heartbeat(self) -> None:
        """
        Send a protocol heartbeat, if required to keep the connection alive.

        Override only for protocols that require an explicit heartbeat.
        """
        if self.socket:
            self.socket.sendall(self.HEARTBEAT)

    def preprocess_stream(self, data: bytes) -> bytes:
        """
        Process raw bytes received from the socket stream.

        Override only if the protocol requires stream-level processing.
        The default implementation returns the input unchanged.
        """
        return data

    def extract_packets(self) -> Iterable[bytes]:
        """
        Extract complete protocol packets from the receive buffer.

        Override to implement protocol-specific packet framing. Complete
        packets should be yielded while consumed bytes are removed from
        the receive buffer.
        """
        pass

    def decode_packet(self, packet: bytes) -> bytes:
        """
        Decode/decrypt a protocol packet.

        Override if the protocol applies packet-level transformations,
        such as encryption, compression or encoding.
        The default implementation returns the packet unchanged.
        """
        return packet

    def extract_messages(self, packet: bytes) -> Iterable[bytes]:
        """
        Extract one or more protocol messages from a decoded packet.

        Override if a packet may contain multiple messages or uses a
        protocol-specific message format. Each yielded message should be ready for parsing.
        The default implementation yields the packet as a message.
        """
        yield packet

    def get_message_type(self, message: bytes) -> MessageType:
        """
        Determine the message type.

        Implementations should identify ACK, HEARTBEAT and ATTACK messages
        whenever possible. COMMAND is the fallback for messages that cannot
        be classified more specifically.
        """
        return MessageType.COMMAND

    def handle_message(self, message: bytes, message_type: MessageType) -> None:
        """
        Handle protocol-specific actions for a received message.

        Override to send protocol replies, such as acknowledgements or heartbeat responses,
        required by the protocol. The default implementation does nothing.
        """
        pass