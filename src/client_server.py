import asyncio
import time
from asyncio import StreamReader, StreamWriter

import cryptography.exceptions
import _pickle as cpickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import user
from packet import Packet
from user import User


class Server:
    def __init__(self, sid: int, send_addr: tuple[str, int], pub_key: Ed25519PublicKey, agreed: bool,
                 shared_key: bytes = None, users: list[str] = None):
        if users is None:
            users = []
        self.id = sid
        self.send_addr = send_addr
        self.recv_addr = None
        self.pub_key: Ed25519PublicKey = pub_key
        self.shared_key: bytes | None = shared_key
        self.agreed: bool = agreed
        self.users: list[str] = users


class ClientServer:
    def __init__(self, port: int, sid: int):
        self.sid: int = sid
        self.__users: list[User] = []
        self.__servers: list[Server] = []
        # with open(f"server{self.sid}_key.txt", 'wb') as ff:
        #     self.__private_key = Ed25519PrivateKey.generate()
        #     ff.write(self.__private_key.private_bytes_raw())

        with open(f"server{self.sid}_key.txt", 'rb') as ff:
            bb = ff.read()
            self.__private_key = Ed25519PrivateKey.from_private_bytes(bb)

        self.__public_key = self.__private_key.public_key()
        self.__hostport: int = port

    async def run(self):
        await asyncio.gather(self.server(),
                             self.check_outbound_msgs())

    async def server(self):
        print(f"Starting: {self.__hostport}")
        server = await asyncio.start_server(self.listen, 'localhost', self.__hostport)
        async with server:
            await server.serve_forever()

    async def listen(self, reader: StreamReader, writer: StreamWriter):
        while True:
            packet = await reader.read(2048)
            if not packet:
                print("Empty")
                break
            addr = writer.get_extra_info('peername')
            print("Received")
            self.receive_message(packet, addr[0], addr[1])
            print("Processed")
        writer.close()
        print("Closed")

    def receive_message(self, message: bytes, hostname: str, port: int):
        print("received message")
        signature = message[:64]

        for server in self.__servers:
            # if server.addr == (hostname, port):
            if server.recv_addr is None or server.recv_addr != (hostname, port):
                print(f"Updating server {server.id} addr to {hostname}, {port}")
                server.recv_addr = (hostname, port)
            try:
                server.pub_key.verify(signature, message[64:])

                if server.agreed:
                    # TODO: randomize the salt in some way
                    msg_key, nonce = user.mk_kdf(server.shared_key, salt=10)
                    aesgcm = AESGCM(msg_key)
                    pt = aesgcm.decrypt(nonce, message[:64], associated_data=None)
                    packet: Packet = cpickle.loads(pt)

                    for usr in self.__users:
                        if packet.dest == usr.get_uid():
                            usr.receive(packet.pack_encrypted)
                            break
                else:
                    self.handshake(server, message)
            except cryptography.exceptions.InvalidSignature:
                print("Invalid Signature")
                return

    def handshake(self, server: Server, message: bytes | None):
        if message is None:
            xpriv = X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()

            server.shared_key = xpriv.private_bytes_raw()

            signature = self.__private_key.sign(xpub)
            new_msg = signature + xpub
            print("Initializing Handshake")
            self.send_message(new_msg, server)
        if not server.shared_key:
            xpriv = X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()

            src_pub = X25519PublicKey.from_public_bytes(message[64:])
            server.shared_key = xpriv.exchange(src_pub)
            server.agreed = True
            print("Agreed 1")

            signature = self.__private_key.sign(xpub)
            new_msg = signature + xpub
            self.send_message(new_msg, server)
        else:
            xpriv = X25519PrivateKey.from_private_bytes(server.shared_key)
            src_pub = X25519PublicKey.from_public_bytes(message[64:])
            server.shared_key = xpriv.exchange(src_pub)
            server.agreed = True
            print("Agreed 2")

    async def send_message(self, message: Packet | bytes, server: Server):
        print("opening conn")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server.send_addr[0], server.send_addr[1]),
                timeout=10.0  # 10 seconds timeout
            )
            print("Connection established")
        except asyncio.TimeoutError:
            print("Connection attempt timed out")
        print("failed")

        if type(message) is Packet:
            if not server.agreed:
                self.handshake(server, None)
            else:
                serialized = cpickle.dumps(message)
                # TODO: randomize the salt in some way
                msg_key, nonce = user.mk_kdf(server.shared_key, salt=10)

                aesgcm = AESGCM(msg_key)
                ct = aesgcm.encrypt(nonce, serialized, associated_data=None)

                signature = self.__private_key.sign(ct)
                packet = signature + ct
                writer.write(packet)
        else:
            writer.write(message)

        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def check_outbound_msgs(self):
        print(f"SID: {self.__hostport}")
        while True:
            # print(f"checking {self.__users[0].get_uid()}")
            for usr in self.__users:
                packets = usr.get_send_queue()
                if usr.get_uid() == "Bob":
                    print(f"packets: {packets}")
                    print(f"user: {usr.get_uid()}")
                    time.sleep(5)
                if packets:
                    print("sending")
                    for packet in packets:
                        dest_usr = packet.dest
                        for server in self.__servers:
                            if dest_usr in server.users:
                                print("passed if")
                                await self.send_message(packet, server)
                                break

    def add_user(self, usr: User):
        self.__users.append(usr)

    def remove_user(self, usr: User):
        self.__users.remove(usr)

    def add_server(self, server: Server):
        self.__servers.append(server)

    def remove_server(self, server: Server):
        self.__servers.remove(server)

    def get_public_key(self):
        return self.__public_key
