import base64
from dataclasses import dataclass, asdict
from enum import Enum

import yaml


class Flags(Enum):
    HELLO = "hello"
    HANDSHAKE = "nice to meet you"
    BEGIN = "begin double ratchet"
    MESSAGE = "message"
    VOTE = "vote"
    BYE = "bye"


@dataclass
class Header(yaml.YAMLObject):
    yaml_tag = u'!Header'
    yaml_loader = yaml.SafeLoader
    src: str
    flags: list[Flags]
    pk: bytes
    pn: int = 0
    nn: int = 0

    @classmethod
    def to_yaml(cls, representer, node):
        encoded_pk = base64.b64encode(node.pk).decode('ascii')
        flags_encoded = [flag.value for flag in node.flags]
        return representer.represent_mapping(cls.yaml_tag, {
            'src': node.src,
            'flags': flags_encoded,
            'pk': encoded_pk,
            'pn': node.pn,
            'nn': node.nn,
        })

    @classmethod
    def from_yaml(cls, loader, node):
        data = loader.construct_mapping(node)
        decoded_pk = base64.b64decode(data['pk'])
        flags_decoded = [Flags(flag) for flag in data['flags']]
        return cls(src=data['src'],
                   flags=flags_decoded,
                   pk=decoded_pk,
                   pn=data['pn'],
                   nn=data['nn'])


@dataclass
class PackEncrypted(yaml.YAMLObject):
    yaml_tag = u'!PackEncrypted'
    yaml_loader = yaml.SafeLoader
    header: bytes
    nonce: bytes = b'0'
    message: bytes = b'0'

    @classmethod
    def to_yaml(cls, representer, node):
        encoded_header = base64.b64encode(node.header).decode('ascii')
        encoded_nonce = base64.b64encode(node.nonce).decode('ascii')
        encoded_message = base64.b64encode(node.message).decode('ascii')
        return representer.represent_mapping(cls.yaml_tag, {
            'header': encoded_header,
            'nonce': encoded_nonce,
            'message': encoded_message,
        })

    @classmethod
    def from_yaml(cls, loader, node):
        data = loader.construct_mapping(node)
        decoded_header = base64.b64decode(data['header'])
        decoded_nonce = base64.b64decode(data['nonce'])
        decoded_message = base64.b64decode(data['message'])
        return cls(header=decoded_header,
                   nonce=decoded_nonce,
                   message=decoded_message)


@dataclass
class Packet(yaml.YAMLObject):
    yaml_tag = u'!Packet'
    yaml_loader = yaml.SafeLoader
    src: str
    dest: str
    pack_encrypted: bytes | PackEncrypted

    @classmethod
    def to_yaml(cls, representer, node):
        if isinstance(node.pack_encrypted, bytes):
            encoded_pack_encrypted = base64.b64encode(node.pack_encrypted).decode('ascii')
            pack_encrypted_data = encoded_pack_encrypted
        else:
            pack_encrypted_data = node.pack_encrypted
        return representer.represent_mapping(cls.yaml_tag, {
            'src': node.src,
            'dest': node.dest,
            'pack_encrypted': pack_encrypted_data,
        })

    @classmethod
    def from_yaml(cls, loader, node):
        data = loader.construct_mapping(node)
        if isinstance(data['pack_encrypted'], str):
            decoded_pack_encrypted = base64.b64decode(data['pack_encrypted'])
        else:
            decoded_pack_encrypted = data['pack_encrypted']
        return cls(src=data['src'],
                   dest=data['dest'],
                   pack_encrypted=decoded_pack_encrypted)


yaml.add_representer(Header, Header.to_yaml)
yaml.add_constructor(Header.yaml_tag, Header.from_yaml)
yaml.add_representer(PackEncrypted, PackEncrypted.to_yaml)
yaml.add_constructor(PackEncrypted.yaml_tag, PackEncrypted.from_yaml)
yaml.add_representer(Packet, Packet.to_yaml)
yaml.add_constructor(Packet.yaml_tag, Packet.from_yaml)
