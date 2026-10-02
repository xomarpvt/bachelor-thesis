from abc import ABC, abstractmethod

class BotnetInterface(ABC):
    """Base interface for botnet traffic detectors."""

    @abstractmethod
    def __init__(self, logger, ip_lookup):
        self.logger = logger
        self.ip_lookup = ip_lookup

    @abstractmethod
    def connect(self):
        """
        Initializes or restores the connection.

        Called once before sniffing starts and again whenever `sniff()`
        terminates unexpectedly.
        """
        pass

    @abstractmethod
    def sniff(self):
        """
        Runs indefinitely, keeps connection alive and yields detected messages.

        Yields:
            dict: Message objects matching the expected schema.
        """
        pass