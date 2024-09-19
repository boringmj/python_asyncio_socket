from tcp_quick.server import Server, Connect
import traceback

# 如果你想要使用ssl,请取消下面的注释
from tcp_quick.cert_manager import CertManager
import os, ssl


user = {"abc": "123", "kkk": "111"}


class MyServer(Server):

    online_users: dict[str] = {}

    async def _handle(self, connect: Connect) -> None:
        addr = connect.peername()
        print(f"{addr}:已连接")
        user_name = (await connect.recv(60)).decode()
        password = (await connect.recv(60)).decode()
        if not await self.login(user_name, password):
            await self.send_utf(connect, "用户名或密码错误")
            raise Exception("登录失败")
        await self.send_utf(connect, "登录成功")

        self.online_users[user_name] = connect
        # 循环接收客户端数据
        while True:
            data = await connect.recv()
            full_data = data.decode()
            print(f"{addr}: {full_data}")
            if full_data.startswith("@"):
                target, msg = full_data[1:].split(" ", 1)
                if target not in self.online_users:
                    await self.send_utf(connect, "用户不存在")
                await self.send_utf(self.online_users[target], f"{user_name}:{msg}")

    async def _error(self, addr, e: Exception) -> None:
        pass
        print(f"来自 {addr} 的连接出现错误: {e}")
        # 如果你想要更详细的错误信息,可以使用traceback模块
        traceback_details = "".join(
            traceback.format_exception(type(e), e, e.__traceback__)
        )
        print(traceback_details)

    async def _connection_closed(self, addr: tuple[str, int], connect: Connect) -> None:
        for u in self.online_users:
            if self.online_users[u].peername() == addr:
                del self.online_users[u]
                break
        await self.close(connect)

    async def send_utf(self, connect: Connect, msg: str | bytes, **args):
        if type(msg) == str:
            msg = msg.encode()
        await self.send(connect, msg, **args)

    async def login(self, user_name: str, password: str) -> bool:
        if user_name in user and user[user_name] == password:
            return True
        else:
            return False


server = MyServer(listen_keywords=True, use_line=False, use_aes=False)
