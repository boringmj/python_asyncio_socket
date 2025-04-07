from abc import ABC,abstractmethod

class BaseConnect(ABC):
    """
    连接的基类
    """

    @abstractmethod
    async def recv(self,timeout:int=0)->bytes:
        """
        接收数据
        :param timeout: 超时时间
        """
        pass

    @abstractmethod
    async def recv_raw(self,size:int,timeout:int=0)->bytes:
        """
        接收原始数据
        :param size: 接收大小
        :param timeout: 超时时间
        """
        pass

    @abstractmethod
    async def send(self,data:bytes,timeout:int=0)->None:
        """
        发送数据
        :param data: 发送数据
        :param timeout: 超时时间
        """
        pass

    @abstractmethod
    async def send_raw(self,data:bytes,timeout:int=0)->None:
        """
        发送原始数据
        :param data: 发送数据
        :param timeout: 超时时间
        """
        pass

    @abstractmethod
    async def recv_raw_line(self,size:int,timeout:int=0)->bytes:
        """
        接收原始行数据
        :param size: 接收大小
        :param timeout: 超时时间
        """
        pass

    @abstractmethod
    async def close(self)->None:
        """
        关闭连接
        """
        pass

    async def initialize(self)->None:
        """
        初始化
        """
        pass