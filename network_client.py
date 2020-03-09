"""
This is a basic implementation of a client for a cryptocurrency
"""

import os
import socket
import sys
import threading

from Crypto.Hash import RIPEMD160
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from blockchain import Block
from blockchain import Blockchain
from blockchain import Transaction
from blockchain import TransactionInput
from blockchain import TransactionOutput


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
    Tomado de https://www.binarytides.com/receive-full-data-with-the-recv-socket-function-in-python/
    :param the_socket:
    :param timeout:
    :return:
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

class Client(object):

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
                    print(data[1:])
                elif data[0:1] == '\x13':
                    print('==> Blockchain downloaded.')
                    blockchain_info = data[1:]
                    self.blockchain = Blockchain(serialization=blockchain_info)
                    update_blockchain_file(self.blockchain.serialize())
                elif data[0:1] == '\x12':
                    print('==> New mined block.')
                    block_info = data[1:]
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

    # BE CAREFUL !! THIS METHOD IS FOR DEMONSTRATIONS ONLY. In a real implementation, this method does not exists.
    def create_gift_coin(self, blockchain):
        """
        This method creates a new coin for the new client
        """
        # Get address of the client
        hash_public_key = self.hash_pubkey()

        coin_gift_tx_input = TransactionInput(prev_tx="1" * 64, pk_spender="1" * 64, signature=bytes("\x11" * 64, encoding="utf-8"))
        coin_gift_tx_output = TransactionOutput(value=100, hash_pubkey_recipient=hash_public_key)
        coin_gift_tx = Transaction(tx_input=coin_gift_tx_input, tx_output=coin_gift_tx_output)

        transactions = [coin_gift_tx]

        nonce = 0
        new_block = None
        while True:
            if len(blockchain.blocks) != 0:
                hash_prev_block = blockchain.blocks[len(blockchain.blocks) - 1].get_hash()
                new_block = Block(transactions, nonce, hash_prev_block)
            else:
                new_block = Block(transactions=transactions, nonce=nonce, prev_block_hash="0" * 64)

            if new_block.get_hash().startswith("0" * blockchain.difficulty):
                print("Nonce found:", nonce)
                break

            nonce += 1

        print(coin_gift_tx.serialize())
        message = "\x12" + new_block.serialize()
        self.socket.sendall(message.encode('utf-8'))

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

            if input_command.startswith("cmd_new_tx"):

                # Show available transactions
                block_number = 0
                print("==> List of available transactions:")
                print(self.blockchain.blocks)
                tx_unspent_counter = 0
                for block in self.blockchain.blocks:
                    transaction_number = 0
                    for transaction in block.transactions:
                        if transaction.tx_output.hash_pubkey_recipient == self.hash_pubkey() and \
                                not transaction.is_already_spent(self.blockchain):
                            tx_unspent_counter += 1
                            print("\t -- [ B:", block_number, " - T:", transaction_number, "]", "Value:", transaction.tx_output.value)
                        transaction_number += 1
                    block_number += 1

                if tx_unspent_counter > 0:
                    block_number_spend = int(input("\tSelect block number: "))
                    transaction_number_spend = int(input("\tSelect transaction number: "))

                    transaction_spend = self.blockchain.blocks[block_number_spend].transactions[transaction_number_spend]
                    address = input("\tAddress: ")
                    value = int(input("\tValue: "))

                    signature_information = transaction_spend.get_hash() + \
                        transaction_spend.tx_output.hash_pubkey_recipient + \
                        address + \
                        str(value)

                    route_private_key = "private_keys/" + str(self.socket.getsockname()[1]) + "_private_key.pem"
                    hash_message = SHA256.new(signature_information.encode("utf-8"))
                    private_key = ECC.import_key(open(route_private_key).read())
                    signer = DSS.new(private_key, "fips-186-3")
                    signature = signer.sign(hash_message)

                    new_tx_input = TransactionInput(prev_tx=transaction_spend.get_hash(), signature=signature, pk_spender=self.load_public_key())
                    new_tx_output = TransactionOutput(value=value, hash_pubkey_recipient=address)

                    new_transaction = Transaction(tx_input=new_tx_input, tx_output=new_tx_output)
                    print("\t-- Signing and sending transaction.")
                    message = "\x10" + new_transaction.serialize()
                else:
                    print("\t-- You do not have unspent transactions")

            elif input_command.startswith("cmd_show_addresses"):
                # This is not a server command
                send_message_to_server = False

                base_path = "public_keys/"
                for file in os.listdir(base_path):
                    pubkey_file = open(base_path + file)
                    pubkey = pubkey_file.read()

                    hash_object = RIPEMD160.new(data=pubkey.encode("utf-8"))
                    print("\t>>", hash_object.hexdigest(), "[", file, "]")

                    pubkey_file.close()

            elif input_command.startswith("cmd_gift"):
                send_message_to_server = False
                self.create_gift_coin(self.blockchain)
            else:
                message = input_command

            if send_message_to_server:
                self.socket.sendall(message.encode('utf-8'))

    def receive_message(self):
        try:
            #data = self.socket.recv(self.byte_size)
            data = recv_timeout(self.socket)
            return data
        except KeyboardInterrupt:
            self.send_disconnect_signal()

    def send_disconnect_signal(self):
        print('==> Disconnected from server.')
        self.socket.sendall("q".encode('utf-8'))
        sys.exit()


class Server(object):

    def __init__(self, byte_size):
        try:

            # List with connections to the server
            self.connections = []

            # List of peers connected
            self.peers = []

            # Socket instantiation and setup
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to local host
            self.socket.bind(('127.0.0.1', 5000))

            self.socket.listen(1)

            self.byte_size = byte_size

            print('==> Server running.')

            self.blockchain = self.load_blockchain()

            # Listen to new connections
            while True:
                connection_handler, ip_port_tuple = self.socket.accept()

                # Add the new peer and send to clients the new list
                self.peers.append(ip_port_tuple)
                self.send_peers()
                self.connections.append(connection_handler)

                # Initialize the handler thread
                handler_thread = threading.Thread(target=self.handler, args=(connection_handler, ip_port_tuple,))
                handler_thread.daemon = True
                handler_thread.start()

                print('==> {} connected.'.format(ip_port_tuple))

                # Send blockchain to new clients
                blockchain_message = "\x13" + self.blockchain.serialize()
                connection_handler.sendall(blockchain_message.encode("utf-8"))
                print("==> Blockchain sent to", ip_port_tuple)

        except Exception as exception:
            print(exception)
            sys.exit()

    def load_blockchain(self):
        """
        Creates a new blockchain if necessary and saves it into disk, or load the blockchain from disk.
        :return: The saved blockchain, otherwise it creates a new Blockchain
        """
        try:
            blockchain_file = open("blockchain_file.txt")
            print("==> Blockchain loaded from file")
            blockchain_info = blockchain_file.read()
            loaded_blockchain = Blockchain(serialization=blockchain_info)
            blockchain_file.close()
            return loaded_blockchain
        except FileNotFoundError:
            print("==> Creating new blockchain")
            new_blockchain = Blockchain(difficulty=3)
            update_blockchain_file(new_blockchain.serialize())
            return new_blockchain

    def handler(self, connection_handler, ip_port_tuple):
        try:
            while True:
                #data = connection_handler.recv(self.byte_size)
                data = recv_timeout(connection_handler)
                # Check if the peer wants to disconnect
                for connection in self.connections:
                    if data and data == 'cmd_show_peers':
                        connection.sendall(('---' + str(self.peers)).encode('utf-8'))
                    elif data and data[0:1] == "\x12":
                        print("==> New mined block.")
                        new_block_info = data[1:]
                        new_block = Block(serialization=new_block_info)

                        in_blockchain = False
                        if len(new_block.transactions) > 1:
                            for block in self.blockchain.blocks:
                                if new_block.equal_blocks(block):
                                    print("==> This block is already mined and is in your blockchain. It will not be added to server blockchain")
                                    in_blockchain = True
                                    break

                        if not in_blockchain:
                            print("\t", new_block.__dict__)
                            print("\tNew Block Hash:", new_block.get_hash())
                            self.blockchain.add_block(new_block)
                            update_blockchain_file(self.blockchain.serialize())

                        connection.sendall(data.encode("utf-8"))
                    elif data:
                        connection.sendall(data.encode("utf-8"))
        except ConnectionResetError:
            print("==> " + str(ip_port_tuple) + " disconnected")
            self.connections.remove(connection_handler)
            connection_handler.close()
            self.peers.remove(ip_port_tuple)
            self.send_peers()

    def send_peers(self):
        peer_list = ""
        for peer in self.peers:
            peer_list += str(peer[0]) + ','

        for connection in self.connections:
            connection.sendall(bytes('\x11' + peer_list, 'utf-8'))

        print('==> Peers sent.')


class Miner(object):
    # TODO implement Miner
    pass
