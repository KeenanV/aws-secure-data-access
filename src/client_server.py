import asyncio
import base64
import random
import time
from asyncio import StreamReader, StreamWriter

import cryptography.exceptions
import _pickle as cpickle

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import user
from packet import Packet
from user import User


class Server(yaml.YAMLObject):
    yaml_tag = u'!Server'
    yaml_loader = yaml.SafeLoader

    def __init__(self, sid: int, send_addr: tuple[str, int], pub_key: Ed25519PublicKey, agreed: bool,
                 verified: bool = False, shared_key: bytes = None, users: list[str] = None):
        if users is None:
            users = []
        self.sid = sid
        self.send_addr = send_addr
        self.recv_addr = None
        self.pub_key: Ed25519PublicKey = pub_key
        self.shared_key: bytes | None = shared_key
        self.agreed: bool = agreed
        self.verified: bool = verified
        self.users: list[str] = users
        self.vnum: list[int] = [0, 0]
        self.reader: StreamReader | None = None
        self.writer: StreamWriter | None = None

    @classmethod
    def to_yaml(cls, representer, node):
        pub_key = node.pub_key.public_bytes_raw() if node.pub_key else None
        d = {
            'sid': node.sid,
            'send_host': node.send_addr[0],
            'send_port': node.send_addr[1],
            'pub_key': base64.b64encode(pub_key).decode('ascii') if pub_key else None,
            'shared_key': base64.b64encode(node.shared_key).decode('ascii') if node.shared_key else None,
            'agreed': node.agreed,
            'verified': node.verified,
            'users': node.users,
        }
        return representer.represent_mapping(cls.yaml_tag, d)

    @classmethod
    def from_yaml(cls, loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            value = loader.construct_object(value_node)
            # If the value is a Base64 encoded string, decode it
            if key in ['pub_key', 'shared_key'] and value is not None:
                value = base64.b64decode(value)

            if key == 'pub_key':
                value = Ed25519PublicKey.from_public_bytes(value)

            result[key] = value

        # Combine 'send_host' and 'send_port' into a tuple under 'send_addr'
        send_host = result.pop('send_host', None)
        send_port = result.pop('send_port', None)
        if send_host is not None and send_port is not None:
            result['send_addr'] = (send_host, send_port)

        return cls(**result)


yaml.add_representer(Server, Server.to_yaml)
yaml.add_constructor(Server.yaml_tag, Server.from_yaml)


class ClientServer(yaml.YAMLObject):
    yaml_tag = u'!ClientServer'
    yaml_loader = yaml.SafeLoader

    def __init__(self, port: int, sid: int, users: list[User] = None, servers: list[Server] = None,
                 priv_key: Ed25519PrivateKey = None):
        self.sid: int = sid
        self.__users: list[User] = users if users else []
        self.__servers: list[Server] = servers if servers else []
        # with open(f"server{self.sid}_key.txt", 'wb') as ff:
        #     self.__private_key = Ed25519PrivateKey.generate()
        #     ff.write(self.__private_key.private_bytes_raw())

        # with open(f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/server{self.sid}_key",
        #           'rb') as ff:
        #     bb = ff.read()
        #     self.__private_key = Ed25519PrivateKey.from_private_bytes(bb)

        self.__private_key = priv_key if priv_key else Ed25519PrivateKey.generate()
        self.__public_key = self.__private_key.public_key()
        self.__hostport: int = port

    @classmethod
    def to_yaml(cls, representer, node):
        priv_key = node.__private_key.private_bytes_raw() if node.__private_key else None
        d = {
            'sid': node.sid,
            'port': node.__hostport,
            'servers': node.__servers,
            'private_key': base64.b64encode(priv_key).decode('ascii') if priv_key else None,
        }

        usrs = []
        for usr in node.__users:
            usrs.append(usr.get_uid().lower())

        d['users'] = usrs
        return representer.represent_mapping(cls.yaml_tag, d)

    @classmethod
    def from_yaml(cls, loader, node):
        # Convert the YAML node to a Python dict
        data = loader.construct_mapping(node, deep=True)

        # Process each attribute of User
        sid = data.get('sid')
        port = data.get('port')
        usernames = data.get('users', [])
        servers = data.get('servers', [])
        priv_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(data.get('private_key')))

        users = []
        for usr in usernames:
            with open(f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/{usr}_yaml.yaml",
                      "r") as ff:
                usr_yaml = ff.read()
            users.append(yaml.safe_load(usr_yaml))

        return cls(port=port,
                   sid=sid,
                   users=users,
                   servers=servers,
                   priv_key=priv_key)

    def dump_yaml(self):
        yaml_string = yaml.dump(self)
        print(yaml_string)
        with open(f"server{self.sid}_yaml.yaml", "w") as ff:
            ff.write(yaml_string)

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
        while True:
            # print("listening")
            packet = await reader.read(2048)
            if not packet:
                print("Empty")
                break
            addr = writer.get_extra_info('peername')
            # print("Received")
            await self.receive_message(packet, addr[0], addr[1])
            # print("Processed")
        writer.close()
        print("Closed")

    async def cli_input(self):
        while True:
            loop = asyncio.get_running_loop()
            print("Available users:")
            for usr in self.__users:
                print(f"   - {usr.get_uid()}")
            selected_usr = await loop.run_in_executor(None, input, "Select User: ")
            if 'yaml' in selected_usr:
                self.dump_yaml()
            elif 'exit' in selected_usr:
                break
            else:
                for usr in self.__users:
                    if selected_usr == usr.get_uid():
                        await asyncio.gather(usr.cli_input(), usr.cli_output())

    async def monitor_policies(self, uid: str):
        usr = self.get_user(uid)
        await asyncio.sleep(5)
        await usr.monitor_policies(
            "/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/aws_policy.txt")

    async def receive_message(self, message: bytes, hostname: str, port: int):
        signature = message[:64]
        ct = message[64:]

        for server in self.__servers:
            # if server.addr == (hostname, port):
            if server.recv_addr is None or server.recv_addr != (hostname, port):
                # print(f"Updating server {server.sid} addr to {hostname}, {port}")
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
                                                    dest=str(server.sid),
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
                                                    dest=str(server.sid),
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
                print(f"Invalid Signature From: {server.sid}")
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
                            dest=str(server.sid),
                            pack_encrypted=server.vnum[0].to_bytes(5, 'big'))
            await self.send_message(packet, server)

    async def send_message(self, message: Packet | bytes, server: Server):
        while server.reader is None or server.writer is None:
            # print("opening conn")
            try:
                server.reader, server.writer = await asyncio.open_connection(server.send_addr[0], server.send_addr[1])
                # print("Connection established")
                break
            except:
                print("Connection attempt timed out")
                continue

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
                server.writer.write(packet)
        else:
            server.writer.write(message)

        # TODO: implement method to close session
        # await writer.drain()
        # writer.close()
        # await writer.wait_closed()

    async def check_outbound_msgs(self):
        print(f"SID: {self.sid}")
        wait = True
        while wait is True:
            wait = False
            for server in self.__servers:
                if server.verified is False:
                    if not server.agreed and server.shared_key is None:
                        await asyncio.sleep(random.SystemRandom().randint(0, 100) / 20)
                        if not server.agreed and server.shared_key is None:
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
                if packets:
                    for packet in packets:
                        dest_usr = packet.dest
                        for server in self.__servers:
                            if dest_usr in server.users:
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

    def get_user(self, uid: str) -> User | None:
        for usr in self.__users:
            if usr.get_uid() == uid:
                return usr
        return None


yaml.add_representer(ClientServer, ClientServer.to_yaml)
yaml.add_constructor(ClientServer.yaml_tag, ClientServer.from_yaml)
