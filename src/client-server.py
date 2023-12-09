import cryptography.exceptions
import _pickle as cpickle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import user
from packet import Packet
from user import User


class Server:
    def __init__(self, sid: int, ip_addr, pub_key: Ed25519PublicKey, shared_key: bytes, agreed: bool,
                 users: list[str] = None):
        if users is None:
            users = []
        self.id = sid
        self.ip = ip_addr
        self.pub_key: Ed25519PublicKey = pub_key
        self.shared_key: bytes = shared_key
        self.agreed: bool = agreed
        self.users: list[str] = users


class ClientServer:
    def __init__(self):
        self.__users: list[User] = []
        self.__servers: list[Server] = []
        self.__private_key = Ed25519PrivateKey.generate()
        self.__public_key = self.__private_key.public_key()

    def receive_message(self, message: bytes, hostname):
        signature = message[:64]

        for server in self.__servers:
            if hostname == server.ip:
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
                        if not server.shared_key:
                            xpriv = X25519PrivateKey.generate()
                            xpub = xpriv.public_key().public_bytes_raw()

                            src_pub = X25519PublicKey.from_public_bytes(message[64:])
                            server.shared_key = xpriv.exchange(src_pub)
                            server.agreed = True

                            signature = self.__private_key.sign(xpub)
                            new_msg = signature + xpub
                            self.send_message(new_msg, server)
                        else:
                            xpriv = X25519PrivateKey.from_private_bytes(server.shared_key)
                            src_pub = X25519PublicKey.from_public_bytes(message[64:])
                            server.shared_key = xpriv.exchange(src_pub)
                            server.agreed = True
                except cryptography.exceptions.InvalidSignature:
                    return

    def send_message(self, message: Packet | bytes, server: Server):
        if type(message) is Packet:
            serialized = cpickle.dumps(message)
            # TODO: randomize the salt in some way
            msg_key, nonce = user.mk_kdf(server.shared_key, salt=10)

            aesgcm = AESGCM(msg_key)
            ct = aesgcm.encrypt(nonce, serialized, associated_data=None)

            signature = self.__private_key.sign(ct)
            packet = signature + ct
            # TODO: send packet over udp socket
        else:
            # TODO: send packet over udp socket
            pass

    def check_for_msgs(self):
        for usr in self.__users:
            packets = usr.get_send_queue()
            if packets:
                for packet in packets:
                    dest_usr = packet.dest
                    for server in self.__servers:
                        if dest_usr in server.users:
                            self.send_message(packet, server)
                            break

    def add_user(self, usr: User):
        self.__users.append(usr)

    def remove_user(self, usr: User):
        self.__users.remove(usr)
