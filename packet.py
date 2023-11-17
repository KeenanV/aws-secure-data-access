from dataclasses import dataclass
from enum import Enum


class Flags(Enum):
    HELLO = "hello"
    HANDSHAKE = "nice to meet you"
    BEGIN = "begin double ratchet"
    MESSAGE = "message"
    BYE = "bye"


@dataclass
class Header:
    src: str
    flags: list[Flags]
    pk: bytes
    pn: int = 0
    nn: int = 0


@dataclass
class PackEncrypted:
    header: bytes
    nonce: bytes = b'0'
    message: bytes = b'0'


@dataclass
class Packet:
    src: str
    dest: str
    pack_encrypted: bytes | PackEncrypted
