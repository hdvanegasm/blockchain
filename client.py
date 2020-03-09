from Crypto.Random import random

from network_client import *


def app():
    while True:
        try:
            print("Trying to connect...")
            for peer in P2PNetwork.peers:
                try:
                    client = Client(peer)
                except KeyboardInterrupt:
                    sys.exit(0)
                except Exception:
                    pass

                # If everyone try to be server
                if random.randint(1, 5) == 1:
                    try:
                        server = Server(byte_size=4096)
                    except KeyboardInterrupt:
                        sys.exit(0)
                    except:
                        print("Server is not running")

        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == '__main__':
    app()
