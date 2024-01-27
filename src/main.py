import asyncio
import random
import sys

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client_server import ClientServer, Server
from packet import Header, PackEncrypted, Packet
from user import User, Session


async def main():
    if len(sys.argv) < 3:
        print("Usage: python3 main.py [DEMO] [SERVER ID] [VOTING OPTIONS]")
        print()
        print("Demo: ")
        print("  chat                chat through cli with other users")
        print("  voting              demo the voting system used for policy changes")
        print()
        print("Server ID:")
        print("  1, 2                the SID of the server to use")
        print()
        print("Voting Options: (these are only required if using the 'voting' demo)")
        print("  success             successful round of voting, agreement, and policy changes")
        print("  unresponsive        demonstration of unresponsive server and detection of it")
        print("  unauthorized        demonstration of unauthorized policy changes and detection of them")
        return

    if sys.argv[1] == "chat":
        await cli_chat()
    elif sys.argv[1] == "voting":
        await voting_demo()


async def voting_demo():
    # FUNCTIONAL CLIENT-SERVER WITH USERS LOADED FROM YAML DEMO
    with open(
            f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/server{sys.argv[2]}_yaml.yaml",
            "r") as ff:
        server_yaml = ff.read()

    server: ClientServer = yaml.safe_load(server_yaml)
    print("loaded")

    with open(f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/aws_policy.txt", "r") as ff:
        if sys.argv[2] == "1":
            server.get_user("Bob").set_policies(ff.read())
        elif sys.argv[2] == "2":
            server.get_user("Alice").set_policies(ff.read())
            server.get_user("Alice").set_write_privilege(True)

    if sys.argv[2] == "1":
        await asyncio.gather(server.run(),
                             server.monitor_policies("Bob"),
                             new_policy(server.get_user("Bob"), sys.argv[3]))
    elif sys.argv[2] == "2":
        await asyncio.gather(server.run(),
                             server.monitor_policies("Alice"),
                             new_policy(server.get_user("Alice"), sys.argv[3]))


async def cli_chat():
    with open(
            f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/server{sys.argv[2]}_yaml.yaml",
            "r") as ff:
        server_yaml = ff.read()

    server: ClientServer = yaml.safe_load(server_yaml)
    print("loaded")

    await asyncio.gather(server.run(),
                         server.cli_input())

    # USERS LOADED FROM YAML
    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/src/bob_yaml.yaml", "r") as ff:
    #     bob_yaml = ff.read()
    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/src/alice_yaml.yaml", "r") as ff:
    #     alice_yaml = ff.read()
    #
    # bob: User = yaml.safe_load(bob_yaml)
    # alice: User = yaml.safe_load(alice_yaml)
    #
    # await bob.cli_input()
    # bobs_packs = bob.get_send_queue()
    #
    # while True:
    #     alice.receive(bobs_packs[0].pack_encrypted)
    #     await alice.cli_input()
    #     alice_packs = alice.get_send_queue()
    #
    #     bob.receive(alice_packs[0].pack_encrypted)
    #     await bob.cli_input()
    #     bobs_packs = bob.get_send_queue()

    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/src/server1_yaml.yaml",
    #           "r") as ff:
    #     server_yaml = ff.read()
    # server1: ClientServer = yaml.safe_load(server_yaml)
    #
    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/src/server2_yaml.yaml",
    #           "r") as ff:
    #     server_yaml = ff.read()
    # server2: ClientServer = yaml.safe_load(server_yaml)

    # NEW SERVERS
    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/server1_key", "rb") as ff:
    #     s1_key = Ed25519PrivateKey.from_private_bytes(ff.read())
    #
    # with open("/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/server2_key", "rb") as ff:
    #     s2_key = Ed25519PrivateKey.from_private_bytes(ff.read())
    #
    # server1: ClientServer = ClientServer(1337, 1, priv_key=s1_key)
    # server2: ClientServer = ClientServer(2337, 2, priv_key=s2_key)
    #
    # s1 = Server(sid=1,
    #             send_addr=('localhost', 1337),
    #             pub_key=server1.get_public_key(),
    #             agreed=False,
    #             users=['bob'])
    # s2 = Server(sid=2,
    #             send_addr=('localhost', 2337),
    #             pub_key=server2.get_public_key(),
    #             agreed=False,
    #             users=['alice'])
    #
    # server1.add_server(s2)
    # server2.add_server(s1)


async def new_policy(usr: User, breach: str):
    if breach == "unresponsive" and usr.get_uid() == "Bob":
        await asyncio.sleep(random.SystemRandom().randint(15, 20))
    else:
        await asyncio.sleep(random.SystemRandom().randint(0, 5))
    with open(f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/aws_new_policy.txt",
              "r") as ff:
        if breach == "unauthorized":
            if usr.get_uid() == "Bob":
                return
            usr.new_policy(ff.read(), override=True)
            print("override")
            return
        print("setting policy")
        usr.new_policy(ff.read(), override=False)


if __name__ == '__main__':
    asyncio.run(main())
