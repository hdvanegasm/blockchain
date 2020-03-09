import os
import socket
import sys
import threading

from Crypto.Hash import RIPEMD160
from Crypto.PublicKey import ECC

from blockchain import Block
from blockchain import Blockchain
from blockchain import Transaction
from blockchain import mine_block


class P2PNetwork(object):
    peers = ['127.0.0.1']


def update_peers(peers_string):
    P2PNetwork.peers = peers_string.split(',')[:-1]


def update_blockchain_file(blockchain_info):
    file_blockchain = open("blockchain_file.txt", "w+")
    file_blockchain.write(blockchain_info)
    file_blockchain.close()


def recv_timeout(the_socket, timeout=1):
    """
    Taken from: https://www.binarytides.com/receive-full-data-with-the-recv-socket-function-in-python/
    """
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = []
    data = ''

    # beginning time
    for i in range(5000):
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(str(data, "utf-8"))
        except BlockingIOError:
            pass

    return ''.join(total_data)


class Miner(object):
    def __init__(self, address):
        """
        Initialization method for Client class

        Convention:
        0x10 - New Transaction
        0x11 - New peers
        0x12 - New mined block
        0x13 - Blockchain
        """

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Make the connection
        self.socket.connect((address, 5000))
        self.byte_size = 1024
        self.peers = []
        print('==> Connected to server.')

        self.generate_key_pair()

        client_listener_thread = threading.Thread(target=self.send_message)
        client_listener_thread.start()

        while True:
            try:
                data = self.receive_message()
                if data[0:1] == '\x11':
                    print('==> Got peers.')
                    update_peers(data[1:])
                elif data[0:1] == '\x10':
                    print('==> New transaction.')
                    transaction_info = data[1:]
                    transaction = Transaction(serialization=transaction_info)

                    # Mining block
                    result = mine_block(transaction=transaction, blockchain=self.blockchain, miner_address=self.hash_pubkey())
                    if result["status"]:
                        message = "\x12" + result["new_block"].serialize()
                        print("==> Sending new mined block")
                        self.socket.sendall(message.encode("utf-8"))
                    else:
                        print("==> Invalid transaction. The block have not been mined")
                elif data[0:1] == '\x13':
                    print('==> Blockchain downloaded.')
                    blockchain_info = data[1:]
                    self.blockchain = Blockchain(serialization=blockchain_info)
                    update_blockchain_file(self.blockchain.serialize())
                elif data[0:1] == '\x12':
                    print('==> New mined block.')
                    block_info = data[1:]
                    print("-----------\n", block_info, "-----------\n")
                    new_block = Block(serialization=block_info)

                    in_blockchain = False
                    for block in self.blockchain.blocks:
                        if new_block.equal_blocks(block):
                            print("==> This block is already mined and is in your blockchain. It will not be added")
                            in_blockchain = True
                            break

                    if not in_blockchain:
                        print("\t", new_block.__dict__)
                        print("\tNew Block Hash:", new_block.get_hash())
                        self.blockchain.add_block(new_block)
                        update_blockchain_file(self.blockchain.serialize())

                elif data != "":
                    print("[#] " + data)
            except ConnectionError as error:
                print("==> Server disconnected. ")
                print('\t--' + str(error))
                break

    def generate_key_pair(self):
        """
        Generate key pairs for this client using elliptic curves, in particular, it uses secp256r1 elliptic curve
        """
        print("==> Generating key pairs.")

        route_private_key = "private_keys/" + str(self.socket.getsockname()[1]) + "_private_key.pem"
        route_public_key = "public_keys/" + str(self.socket.getsockname()[1]) + "_public_key.pem"

        key = ECC.generate(curve="secp256r1")
        file_private_key = open(route_private_key, "wt")
        file_private_key.write(key.export_key(format="PEM"))

        file_public_key = open(route_public_key, "wt")
        file_public_key.write(key.public_key().export_key(format="PEM"))

        print("==> Key pairs generated.")
        print("\t" + route_private_key)
        print("\t" + route_public_key)

        file_public_key.close()
        file_private_key.close()

    def hash_pubkey(self):
        public_key = self.load_public_key()

        hash_object = RIPEMD160.new(public_key.encode("utf-8"))
        hash_public_key = hash_object.hexdigest()
        return hash_public_key

    def load_public_key(self):
        route_public_key = "public_keys/" + str(self.socket.getsockname()[1]) + "_public_key.pem"
        file_public_key = open(route_public_key, "r")
        public_key = file_public_key.read()
        file_public_key.close()
        return public_key

    def send_message(self):

        while True:
            input_command = input()

            # This variable is set to True when is a server command
            send_message_to_server = True

            if input_command.startswith("cmd_show_addresses"):
                # This is not a server command
                send_message_to_server = False

                base_path = "public_keys/"
                for file in os.listdir(base_path):
                    pubkey_file = open(base_path + file)
                    pubkey = pubkey_file.read()

                    hash_object = RIPEMD160.new(data=pubkey.encode("utf-8"))
                    print("\t>>", hash_object.hexdigest(), "[", file, "]")

                    pubkey_file.close()
            else:
                message = input_command

            if send_message_to_server:
                self.socket.sendall(message.encode('utf-8'))

    def receive_message(self):
        try:
            data = recv_timeout(self.socket)
            return data
        except KeyboardInterrupt:
            self.send_disconnect_signal()

    def send_disconnect_signal(self):
        print('==> Disconnected from server.')
        self.socket.sendall("q".encode('utf-8'))
        sys.exit()


def app():
    while True:
        try:
            print("Trying to connect...")
            for peer in P2PNetwork.peers:
                try:
                    client = Miner(peer)
                except KeyboardInterrupt:
                    sys.exit(0)

        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == '__main__':
    app()