import asyncio
import sys

from client_server import ClientServer, Server
from user import User


async def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == "Alice":
            pass
        elif sys.argv[0] == "Bob":
            pass
    alice = User("Alice")
    bob = User("Bob")
    server1 = ClientServer(1337, 1)
    server2 = ClientServer(2337, 2)

    s1 = Server(sid=1,
                send_addr=('localhost', 1337),
                pub_key=server1.get_public_key(),
                agreed=False,
                users=["Alice"])
    s2 = Server(sid=2,
                send_addr=('localhost', 2337),
                pub_key=server2.get_public_key(),
                agreed=False,
                users=["Bob"])

    server1.add_user(alice)
    server2.add_user(bob)
    server1.add_server(s2)
    server2.add_server(s1)

    await asyncio.gather(server1.run(),
                         server2.run(),
                         bob.init_session("Alice"))


if __name__ == '__main__':
    asyncio.run(main())