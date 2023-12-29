import asyncio
import random
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
        self.verified: bool = False
        self.users: list[str] = users
        self.vnum: list[int] = [0, 0]


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
        print("server started")
        async with server:
            await server.serve_forever()

    async def listen(self, reader: StreamReader, writer: StreamWriter):
        for ii in range(10):
            print("listening")
            packet = await reader.read(2048)
            if not packet:
                print("Empty")
                break
            addr = writer.get_extra_info('peername')
            print("Received")
            await self.receive_message(packet, addr[0], addr[1])
            print("Processed")
        writer.close()
        print("Closed")

    async def receive_message(self, message: bytes, hostname: str, port: int):
        print("received message")
        signature = message[:64]
        ct = message[64:]

        for server in self.__servers:
            # if server.addr == (hostname, port):
            if server.recv_addr is None or server.recv_addr != (hostname, port):
                print(f"Updating server {server.id} addr to {hostname}, {port}")
                server.recv_addr = (hostname, port)
            try:
                server.pub_key.verify(signature, ct)

                if server.agreed:
                    # TODO: randomize the salt in some way
                    msg_key, nonce = user.mk_kdf(server.shared_key, salt=10)
                    aesgcm = AESGCM(msg_key)
                    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
                    packet: Packet = cpickle.loads(pt)

                    handled = False
                    for usr in self.__users:
                        if packet.dest == usr.get_uid():
                            usr.receive(packet.pack_encrypted)
                            handled = True
                            break

                    if not handled:
                        print(f"Not handled: {packet.dest}, {str(self.sid)}")
                        if packet.dest == str(self.sid):
                            print(f"VNUM: {server.vnum}")
                            if server.vnum == [0, 0]:
                                server.vnum[1] = int.from_bytes(packet.pack_encrypted, 'big')
                                server.vnum[1] += 1
                                rr = random.SystemRandom()
                                server.vnum[0] = rr.randint(100000000, 9999999998)
                                new_packet = Packet(src=str(self.sid),
                                                    dest=str(server.id),
                                                    pack_encrypted=server.vnum[0].to_bytes(5, 'big') + server.vnum[
                                                        1].to_bytes(5, 'big'))
                                await self.send_message(new_packet, server)
                            elif server.vnum[0] != 0 and server.vnum[1] == 0:
                                server.vnum[0] += 1
                                assert server.vnum[0] == int.from_bytes(packet.pack_encrypted[5:], 'big')
                                print(f"Server {self.sid} verified")
                                server.verified = True

                                server.vnum[1] = int.from_bytes(packet.pack_encrypted[:5], 'big')
                                server.vnum[1] += 1
                                new_packet = Packet(src=str(self.sid),
                                                    dest=str(server.id),
                                                    pack_encrypted=server.vnum[1].to_bytes(5, 'big'))
                                await self.send_message(new_packet, server)
                            elif server.vnum[0] != 0 and server.vnum[1] != 0:
                                server.vnum[0] += 1
                                assert server.vnum[0] == int.from_bytes(packet.pack_encrypted, 'big')
                                print(f"Server {self.sid} verified")
                                server.verified = True

                else:
                    await self.handshake(server, message)
            except cryptography.exceptions.InvalidSignature:
                print("Invalid Signature")
                return

    async def handshake(self, server: Server, message: bytes | None):
        if message is None:
            xpriv = X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()

            server.shared_key = xpriv.private_bytes_raw()

            signature = self.__private_key.sign(xpub)
            new_msg = signature + xpub
            print("Initializing Handshake")
            await self.send_message(new_msg, server)
        elif not server.shared_key:
            xpriv = X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()

            src_pub = X25519PublicKey.from_public_bytes(message[64:])
            server.shared_key = xpriv.exchange(src_pub)
            server.agreed = True
            print("Agreed 1")

            signature = self.__private_key.sign(xpub)
            new_msg = signature + xpub
            await self.send_message(new_msg, server)
        else:
            xpriv = X25519PrivateKey.from_private_bytes(server.shared_key)
            src_pub = X25519PublicKey.from_public_bytes(message[64:])
            server.shared_key = xpriv.exchange(src_pub)
            server.agreed = True
            print("Agreed 2")
            rr = random.SystemRandom()
            server.vnum[0] = rr.randint(100000000, 9999999998)
            packet = Packet(src=str(self.sid),
                            dest=str(server.id),
                            pack_encrypted=server.vnum[0].to_bytes(5, 'big'))
            await self.send_message(packet, server)

    async def send_message(self, message: Packet | bytes, server: Server):
        print("opening conn")
        try:
            reader, writer = await asyncio.open_connection(server.send_addr[0], server.send_addr[1])
            print("Connection established")
        except asyncio.TimeoutError:
            print("Connection attempt timed out")
            return

        if type(message) is Packet:
            if not server.agreed:
                await self.handshake(server, None)
            else:
                serialized = cpickle.dumps(message)
                # TODO: randomize the salt in some way
                msg_key, nonce = user.mk_kdf(server.shared_key, salt=10)

                aesgcm = AESGCM(msg_key)
                ct = aesgcm.encrypt(nonce, serialized, associated_data=None)

                signature = self.__private_key.sign(ct)
                packet = signature + ct
                writer.write(packet)
                print("Verified sent")
        else:
            writer.write(message)

        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def check_outbound_msgs(self):
        print(f"SID: {self.__hostport}")
        wait = True
        while wait is True:
            wait = False
            for server in self.__servers:
                if server.verified is False:
                    if not server.agreed and self.sid == 1:
                        await self.handshake(server, None)
                    wait = True
                    break
                await asyncio.sleep(0)
            await asyncio.sleep(0.1)
        while True:
            # print(f"checking {self.__users[0].get_uid()}")
            for usr in self.__users:
                # print("Got send queue")
                packets = usr.get_send_queue()
                if usr.get_uid() == "Bob":
                    pass
                    # print(f"packets: {packets}")
                    # print(f"user: {usr.get_uid()}")
                    # await asyncio.sleep(5)
                if packets:
                    # print("sending")
                    for packet in packets:
                        dest_usr = packet.dest
                        for server in self.__servers:
                            if dest_usr in server.users:
                                # print("passed if")
                                await self.send_message(packet, server)
                                break
                await asyncio.sleep(0)
            await asyncio.sleep(0.1)

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
