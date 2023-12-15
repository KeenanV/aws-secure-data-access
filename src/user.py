import os
import random
import _pickle as cpickle

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packet import PackEncrypted, Flags, Header, Packet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


class Session:
    def __init__(self, uid: str, dhs, rk=None, dhr: X25519PublicKey | None = None,
                 cks: bytes | None = None, ckr: bytes | None = None, ns=-1, nr=-1, pn=0, mkskipped=None):
        if mkskipped is None:
            mkskipped = {}
        self.uid: str = uid
        self.dhs = dhs
        self.dhr: X25519PublicKey | None = dhr
        self.rk = rk
        self.cks: bytes | None = cks
        self.ckr: bytes | None = ckr
        self.ns: int = ns
        self.nr: int = nr
        self.pn: int = pn
        self.verify: int = 0
        self.mkskipped: dict = mkskipped
        self.agreed: bool = False


def mk_kdf(msg_key: bytes, salt=0) -> tuple[bytes, bytes]:
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=48,
                salt=salt.to_bytes(48, 'big'),
                info=b'msg encryption')
    keys = hkdf.derive(msg_key)
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=48,
                salt=salt.to_bytes(48, 'big'),
                info=b'msg encryption')
    hkdf.verify(msg_key, keys)

    mk = keys[0:32]
    nonce = keys[32:48]
    return mk, nonce


class User:
    def __init__(self, uid: str):
        self.__sessions: list[Session] = []
        self.__send_queue: list[Packet] = []
        self.__uid = uid

    def get_send_queue(self) -> list[Packet]:
        queue = self.__send_queue.copy()
        self.__send_queue.clear()
        return queue

    def get_uid(self) -> str:
        return self.__uid

    def receive(self, packet: PackEncrypted):
        associated_data = packet.header
        header: Header = cpickle.loads(associated_data[8:])

        if Flags.HELLO in header.flags:
            self.__recv_session(header)
        elif Flags.HANDSHAKE in header.flags:
            self.__verify_session(header, packet.nonce, packet.message)
        else:
            for sesh in self.__sessions:
                if sesh.uid == header.src:
                    message, flags = self.__decrypt(packet, sesh)
                    if Flags.BEGIN in flags:
                        verify_num = int(message)
                        if sesh.verify == 0:
                            new_msg = verify_num + 1
                            sesh.ns = 0
                            sesh.pn = 0
                            self.__encrypt(sesh, str(new_msg), [Flags.BEGIN], dh_ratchet=True)
                        else:
                            if verify_num == sesh.verify + 1:
                                sesh.agreed = True
                                new_msg = f"{header.src} the connection is verified"
                                self.__encrypt(sesh, new_msg, [Flags.MESSAGE], dh_ratchet=True)
                            else:
                                self.__sessions.remove(sesh)
                    else:
                        print(f"{self.__uid} received message: {message}")
                        new_msg = f"{self.__uid} sending message to {header.src}"
                        self.__encrypt(sesh, new_msg, [Flags.MESSAGE], dh_ratchet=True)
                    break

    def __send(self, packet: Packet):
        # print(f"sending {packet}")
        self.__send_queue.append(packet)
        # print(f"sent {self.get_send_queue()}")

    async def init_session(self, uid: str):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        new_session = Session(uid=uid,
                              dhs=(private_key, public_key),
                              ns=1)
        self.__sessions.append(new_session)

        header = Header(src=self.__uid,
                        pk=public_key.public_bytes_raw(),
                        flags=[Flags.HELLO])
        associated_data = os.urandom(8) + cpickle.dumps(header)
        pack_enc = PackEncrypted(header=associated_data)
        packet = Packet(src=self.__uid,
                        dest=new_session.uid,
                        pack_encrypted=pack_enc)
        self.__send(packet)

    def __recv_session(self, packet: Header):
        for sesh in self.__sessions:
            if sesh.uid == packet.src:
                return

        # generate new DH keypair
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # create new session with the sending user
        src_pub = X25519PublicKey.from_public_bytes(packet.pk)
        new_session = Session(uid=packet.src,
                              dhs=(private_key, public_key),
                              dhr=src_pub,
                              rk=private_key.exchange(src_pub),
                              nr=1,
                              ns=1)

        # hash the DH shared key to a 256-bit key to be used with AES-GCM encryption
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=packet.pk,
                    info=b'handshake')
        dh_key = new_session.rk
        new_session.rk = hkdf.derive(dh_key)
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=packet.pk,
                    info=b'handshake')
        hkdf.verify(dh_key, new_session.rk)

        # generate random number to verify DH shared key between users
        rr = random.SystemRandom()
        new_session.pn = rr.randint(100000000, 9999999998)
        nn = new_session.pn.to_bytes(5, 'big')

        # encrypt rand num with AES-GCM using DH shared key
        aesgcm = AESGCM(new_session.rk)
        nonce = os.urandom(12)
        msg = aesgcm.encrypt(nonce, nn, None)

        # construct the packet to be sent
        pack_send = self.__handshake_packs(pub_key=public_key,
                                           nonce=nonce,
                                           msg=msg,
                                           destination_user=packet.src)

        self.__sessions.append(new_session)
        self.__send(pack_send)

    def __verify_session(self, header: Header, nonce: bytes, message: bytes):
        for sesh in self.__sessions:
            if sesh.uid == header.src:
                private_key = X25519PrivateKey.generate()
                public_key = private_key.public_key()
                if sesh.rk is None:
                    dh_key = sesh.dhs[0].exchange(X25519PublicKey.from_public_bytes(header.pk))
                    hkdf = HKDF(algorithm=hashes.SHA256(),
                                length=32,
                                salt=sesh.dhs[1].public_bytes_raw(),
                                info=b'handshake')
                    sesh.rk = hkdf.derive(dh_key)
                    hkdf = HKDF(algorithm=hashes.SHA256(),
                                length=32,
                                salt=sesh.dhs[1].public_bytes_raw(),
                                info=b'handshake')
                    hkdf.verify(dh_key, sesh.rk)
                    sesh.dhs = (private_key, public_key)

                    aesgcm = AESGCM(sesh.rk)
                    plaintext = int.from_bytes(aesgcm.decrypt(nonce, message, None), 'big')
                    new_num = plaintext + 1

                    new_nonce = os.urandom(12)
                    new_msg = aesgcm.encrypt(new_nonce, new_num.to_bytes(5, 'big'), None)

                    pack_send = self.__handshake_packs(pub_key=public_key,
                                                       nonce=new_nonce,
                                                       msg=new_msg,
                                                       destination_user=header.src)
                    self.__send(pack_send)
                else:
                    # Decrypt message and verify rand number
                    aesgcm = AESGCM(sesh.rk)
                    plaintext = int.from_bytes(aesgcm.decrypt(nonce, message, None), 'big')
                    if sesh.pn + 1 != plaintext:
                        # TODO: handle MITM
                        print("Handshake number doesn't match")
                        return

                    # Update src public key for the session
                    sesh.dhr = X25519PublicKey.from_public_bytes(header.pk)

                    # Encrypt and send new rand num to begin Double Ratchet comms
                    rr = random.SystemRandom()
                    sesh.verify = rr.randint(100000000, 9999999998)
                    msg = sesh.verify

                    sesh.pn = 0
                    sesh.ns = 0
                    self.__encrypt(sesh, str(msg), [Flags.BEGIN], dh_ratchet=True)

    def __encrypt(self, sesh: Session, message: str, flags: list[Flags], dh_ratchet: bool):
        # Derive message key, authentication key, and nonce from original message key
        if dh_ratchet:
            self.__dh_ratchet(sesh, send=True)
        msg_key = self.__sym_ratchet(sesh, send=True)
        mk, nonce = mk_kdf(msg_key)

        # Build the header and concatenate with random bytes for associated data
        header = Header(src=self.__uid,
                        flags=flags,
                        pk=sesh.dhs[1].public_bytes_raw(),
                        pn=sesh.pn,
                        nn=sesh.ns)
        associated_data = os.urandom(8) + cpickle.dumps(header)

        # Encrypt the message and assemble the packet
        aesgcm = AESGCM(mk)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), associated_data)

        pack_enc = PackEncrypted(header=associated_data,
                                 message=ciphertext)
        pack = Packet(src=self.__uid,
                      dest=sesh.uid,
                      pack_encrypted=pack_enc)
        self.__send(pack)

    def __decrypt(self, packet: PackEncrypted, sesh: Session) -> tuple[str, list[Flags]] | None:
        associated_data = packet.header
        header: Header = cpickle.loads(associated_data[8:])
        src_pub = X25519PublicKey.from_public_bytes(header.pk)

        if sesh.dhr is None or sesh.dhr != src_pub:
            sesh.dhr = src_pub
            self.__dh_ratchet(sesh, send=False)

        mk = self.__sym_ratchet(sesh, send=False)
        msgk, nonce = mk_kdf(mk)

        aesgcm = AESGCM(msgk)
        plaintext = aesgcm.decrypt(nonce, packet.message, associated_data).decode('utf-8')
        sesh.nr += 1

        return plaintext, header.flags

    def __dh_ratchet(self, sesh: Session, send: bool):
        if send:
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            sesh.dhs = (private_key, public_key)

        dh_key = sesh.dhs[0].exchange(sesh.dhr)
        salt = sesh.rk
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    info=b'dh ratchet')

        sesh.rk = hkdf.derive(dh_key)
        if send:
            sesh.cks = sesh.rk
        else:
            sesh.ckr = sesh.rk
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    info=b'dh ratchet')
        hkdf.verify(dh_key, sesh.rk)

    def __sym_ratchet(self, sesh: Session, send: bool) -> bytes:
        if send:
            hm_ck = hmac.HMAC(key=sesh.cks,
                              algorithm=hashes.SHA256())
        else:
            hm_ck = hmac.HMAC(key=sesh.ckr,
                              algorithm=hashes.SHA256())
        hm_mk = hm_ck.copy()

        n2 = 2
        hm_ck.update(n2.to_bytes(1, 'big'))
        if send:
            sesh.cks = hm_ck.finalize()
        else:
            sesh.ckr = hm_ck.finalize()

        n1 = 1
        hm_mk.update(n1.to_bytes(1, 'big'))
        return hm_mk.finalize()

    def __handshake_packs(self, pub_key: X25519PublicKey, nonce: bytes, msg: bytes, destination_user: str) -> Packet:
        header = Header(src=self.__uid,
                        pk=pub_key.public_bytes_raw(),
                        flags=[Flags.HANDSHAKE])
        associated_data = os.urandom(8) + cpickle.dumps(header)
        pack_enc = PackEncrypted(header=associated_data,
                                 nonce=nonce,
                                 message=msg)
        pack_send = Packet(src=self.__uid,
                           dest=destination_user,
                           pack_encrypted=pack_enc)
        return pack_send
