from abc import ABC,abstractmethod

class BaseProtocol(ABC):
    """
    协议的基类
    """

    @abstractmethod
    def handshake(self)->None:
        """
        握手协议,用于在连接建立时进行初始化和验证
        """
        pass