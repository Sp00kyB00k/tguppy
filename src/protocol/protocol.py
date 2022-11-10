from abc import ABC, abstractmethod


class Protocol(ABC):
    """
    Interface for protocol suite
    Meant to deencapsulate a raw packet 
    and breaking it further down
    """

    @abstractmethod
    def next(self) -> str:
        """
        Method to return the next protocol to deencapsulate
        """
        pass
