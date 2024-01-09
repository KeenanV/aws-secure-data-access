import asyncio
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client_server import ClientServer, Server
from user import User


async def main():
    if len(sys.argv) == 7:
        usr = User(sys.argv[1])
        port = int(sys.argv[2])
        sid = int(sys.argv[3])
        s2_usr = sys.argv[4]
        s2_port = int(sys.argv[5])
        s2_sid = int(sys.argv[6])
    else:
        print("Usage: main.py <UID> <port> <SID> <target UID> <target port> <target SID>")
        return

    server = ClientServer(port, sid)
    with open(f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/server{s2_sid}_key.txt", 'rb') as ff:
        bb = ff.read()
        s2_priv_key = Ed25519PrivateKey.from_private_bytes(bb)

    s2 = Server(sid=s2_sid,
                send_addr=('localhost', s2_port),
                pub_key=s2_priv_key.public_key(),
                agreed=False,
                users=[s2_usr])

    server.add_user(usr)
    server.add_server(s2)

    if usr.get_uid() == "Bob":
        await asyncio.gather(server.run(),
                             usr.init_session(s2_usr),
                             usr.cli_input())
    else:
        await asyncio.gather(server.run(),
                             usr.cli_input())


if __name__ == '__main__':
    asyncio.run(main())
