import asyncio
import sys
import yaml
from client_server import ClientServer


async def main():
    with open(
            f"/Users/keenanv/Documents/Programming/Python/double-ratchet-comms/resources/server{sys.argv[1]}_yaml.yaml",
            "r") as ff:
        server_yaml = ff.read()

    server: ClientServer = yaml.safe_load(server_yaml)
    print("loaded")

    await asyncio.gather(server.run(),
                         server.get_user(sys.argv[2]).cli_input())


if __name__ == '__main__':
    asyncio.run(main())
