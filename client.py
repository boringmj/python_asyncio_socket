from tcp_quick.client import Client, Connect
import traceback
import asyncio


class MyClient(Client):
    def __init__(self, user_name="", password="", **kwargs):
        self.user_name = user_name
        self.password = password
        super().__init__(**kwargs)

    async def _handle(self, connect: Connect) -> None:
        """处理连接"""
        await connect.send(self.user_name.encode())
        await connect.send(self.password.encode())
        # 使用 asyncio.create_task 来异步运行输入函数
        self._loop.create_task(self._listen_keyboard_input())
        while True:
            data = await connect.recv()
            print(f"{data.decode()}")

    async def _listen_keyboard_input(self) -> str:
        """非阻塞输入函数"""
        while True:
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(None, input)
            await self.send((await future).encode())

    async def _error(self, e: Exception) -> None:
        pass
        """处理错误"""
        print(f"发生错误:{e}")
        # 如果你想要更详细的错误信息,可以使用traceback模块
        traceback_details = "".join(
            traceback.format_exception(type(e), e, e.__traceback__)
        )
        print(traceback_details)

client = MyClient(user_name="abc", password="123", use_line=False, use_aes=False)
