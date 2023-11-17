import socket

from user import User


class AWSUser:
    def __init__(self, username: str, ip: str, port: int):
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.bind((ip, port))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    alice = User("Alice")
    bob = User("Bob")
    charlie = User("Charlie")

    bob.init_session("Alice")
    charlie.init_session("Bob")
    alice.init_session("Charlie")

    for ii in range(0, 13):
        bob_msg = bob.get_send_queue()
        charlie_msg = charlie.get_send_queue()
        alice_msg = alice.get_send_queue()

        for msg in bob_msg:
            match msg.dest:
                case "Alice":
                    alice.receive(msg.pack_encrypted)
                case "Charlie":
                    charlie.receive(msg.pack_encrypted)

        for msg in charlie_msg:
            match msg.dest:
                case "Alice":
                    alice.receive(msg.pack_encrypted)
                case "Bob":
                    bob.receive(msg.pack_encrypted)

        for msg in alice_msg:
            match msg.dest:
                case "Bob":
                    bob.receive(msg.pack_encrypted)
                case "Charlie":
                    charlie.receive(msg.pack_encrypted)
