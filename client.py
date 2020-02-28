from network_client import *
import random
from network_client import Client, Server


def app():
    while True:
        try:
            print("Trying to connect...")
            for peer in P2PNetwork.peers:
                try:
                    client = Client(peer)
                except KeyboardInterrupt:
                    sys.exit(0)
                except:
                    pass

                # If everyone try to be server
                if random.randint(1, 20) == 1:
                    try:
                        server = Server(byte_size=1024)
                    except KeyboardInterrupt:
                        sys.exit(0)
                    except:
                        print("Server is not running")

        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == '__main__':
    app()
