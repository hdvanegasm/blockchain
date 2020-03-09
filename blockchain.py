from datetime import datetime

from Crypto.Hash import RIPEMD160
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


class Blockchain:

    def __init__(self, difficulty=-1, blocks=[], serialization=None):
        if serialization is None:
            self.blocks = blocks
            self.difficulty = difficulty

            genesis_tx_input = TransactionInput(prev_tx="0" * 64, pk_spender="0" * 64,
                                                signature=bytes("\x11" * 64, encoding="utf-8"))
            genesis_tx_output = TransactionOutput(value=100,
                                                  hash_pubkey_recipient="ef5c3fbad7c48451403b663e0dcd59828c1def5c")
            genesis_tx = Transaction(tx_input=genesis_tx_input, tx_output=genesis_tx_output)

            transactions = [genesis_tx]

            nonce = 0
            genesis_block = None
            while True:
                genesis_block = Block(transactions=transactions, nonce=nonce, prev_block_hash="0" * 64)

                if genesis_block.get_hash().startswith("0" * self.difficulty):
                    print("Nonce found:", nonce)
                    break

                nonce += 1

            self.add_block(genesis_block)

        else:
            blockchain_info = eval(serialization)

            self.difficulty = int(blockchain_info["difficulty"])

            self.blocks = []
            block_info = blockchain_info["blocks"]
            for block_serialization in block_info:
                block_unserialized = Block(serialization=block_serialization)
                self.blocks.append(block_unserialized)

    def is_valid(self):
        for block in self.blocks:
            if not block.get_hash().startswith("0" * self.difficulty):
                return False
        return True

    def serialize(self):
        dictionary_blockchain = self.__dict__.copy()
        serialized_blocks = list()
        for block in self.blocks:
            serialized_blocks.append(block.serialize())

        dictionary_blockchain["blocks"] = serialized_blocks
        return str(dictionary_blockchain)

    def add_block(self, block):
        if block.get_hash().startswith("0" * self.difficulty):
            print("==> New valid block added to blockchain.")
            self.blocks.append(block)


class Block:

    def __init__(self, transactions=None, nonce=None, prev_block_hash=None, serialization=None):
        if serialization is None:
            self.nonce = nonce
            self.prev_block_hash = prev_block_hash
            self.transactions = transactions
        else:
            bloc_information = eval(serialization)

            self.nonce = int(bloc_information["nonce"])
            self.prev_block_hash = bloc_information["prev_block_hash"]

            transactions_serialization = bloc_information["transactions"]
            self.transactions = []
            for transaction_info in transactions_serialization:
                new_tx = Transaction(serialization=transaction_info)
                self.transactions.append(new_tx)

    def get_hash(self):
        block_serialization = self.serialize()
        hash_object = SHA256.new(data=bytes(block_serialization, encoding='utf-8'))
        return hash_object.hexdigest()

    def serialize(self):
        dictionary = self.__dict__.copy()

        transaction_serializations = list()
        for transaction in self.transactions:
            transaction_serializations.append(transaction.serialize())

        dictionary['transactions'] = transaction_serializations
        block_serialization = str(dictionary)
        return block_serialization

    # TODO Fix this
    def equal_blocks(self, other):
        if len(self.transactions) > 1 and len(other.transactions) > 1:
            transaction_self = self.transactions[1]
            transaction_other = other.transactions[1]
            return transaction_self.get_hash() == transaction_other.get_hash()

        elif len(self.transactions) == 1 and len(other.transactions) == 1:
            transaction_self = self.transactions[0]
            transaction_other = other.transactions[0]
            return transaction_self.get_hash() == transaction_other.get_hash()

        else:
            return False


class Transaction:

    def __init__(self, tx_input=None, tx_output=None, serialization=None):
        if serialization is None:
            self.tx_input = tx_input
            self.tx_output = tx_output
        else:
            tx_information = eval(serialization)
            self.tx_input = TransactionInput(serialization=tx_information["tx_input"])
            self.tx_output = TransactionOutput(serialization=tx_information["tx_output"])

    def is_already_spent(self, blockchain):
        for block in blockchain.blocks:
            for transaction in block.transactions:
                if transaction.tx_input.prev_tx == self.get_hash():
                    return True
        return False

    def is_valid(self, blockchain):
        """
        1. Find the prev tx
        2. Extract the output of the tx
        3. Execute the validation script
        4. Return the validation result
        :param blockchain: Blockchain in which we want to validate the transaction.
        :return: If tx is valid, return True, otherwise return False.
        """
        print("\t>> Validating transaction")
        prev_transaction = None
        for block in blockchain.blocks:
            for transaction in block.transactions:
                transaction_hash = transaction.get_hash()
                if transaction_hash == self.tx_input.prev_tx:
                    prev_transaction = transaction

        if prev_transaction is None:
            return False

        print("\t\t-- Found previous transaction")

        # Check values of BTC
        output_value = self.tx_output.value
        prev_transaction_value = prev_transaction.tx_output.value
        if output_value > prev_transaction_value:
            return False

        print("\t\t-- Values are correct")

        # Verifying hash of spender's Pk
        hash_output_prev_tx = prev_transaction.tx_output.hash_pubkey_recipient
        hash_object = RIPEMD160.new(self.tx_input.pk_spender.encode("utf-8"))
        hash_pk_spender = hash_object.hexdigest()

        # Can't spend the money, it's not for you
        if hash_pk_spender != hash_output_prev_tx:
            return False

        print("\t\t-- Pubkey hashes match")

        # Signature validation
        signature_input = self.tx_input.signature

        signature_information = prev_transaction.get_hash() + \
                                prev_transaction.tx_output.hash_pubkey_recipient + \
                                self.tx_output.hash_pubkey_recipient + \
                                str(self.tx_output.value)

        hash_signature_information = SHA256.new(signature_information.encode("utf-8"))
        public_key = ECC.import_key(self.tx_input.pk_spender)

        verifier = DSS.new(public_key, "fips-186-3")

        try:
            verifier.verify(hash_signature_information, signature_input)
            print("\t\t-- Signature verified")
            return True
        except ValueError:
            return False

    def serialize(self):
        dictionary_tx = self.__dict__.copy()
        dictionary_tx["tx_input"] = self.tx_input.serialize()
        dictionary_tx["tx_output"] = self.tx_output.serialize()

        return str(dictionary_tx)

    def get_hash(self):
        tx_serialization = self.serialize()
        hash_object = SHA256.new(data=bytes(tx_serialization, encoding='utf-8'))
        return hash_object.hexdigest()


class TransactionInput:

    def __init__(self, prev_tx="", signature="", pk_spender="", serialization=None):
        # Previous Tx is the hash of the previous Tx
        if serialization is None:
            self.prev_tx = prev_tx
            self.signature = signature
            self.pk_spender = pk_spender
        else:
            tx_input_information = eval(serialization)
            self.prev_tx = tx_input_information["prev_tx"]
            self.signature = tx_input_information["signature"]
            self.pk_spender = tx_input_information["pk_spender"]

    def serialize(self):
        return str(self.__dict__)


class TransactionOutput:

    def __init__(self, value=-1, hash_pubkey_recipient="", serialization=None):
        if serialization is None:
            self.value = value

            # It is the hashed value of the Pk of the recipient
            self.hash_pubkey_recipient = hash_pubkey_recipient
        else:
            tx_output_information = eval(serialization)
            self.value = tx_output_information["value"]
            self.hash_pubkey_recipient = tx_output_information["hash_pubkey_recipient"]

    def serialize(self):
        return str(self.__dict__)


def mine_block(transaction, blockchain, miner_address):
    # Set the incentive with the politic you like
    incentive = 10

    transactions = []

    # Add the coinbase (creation of new coins)
    coinbase_tx_input = TransactionInput(prev_tx="0" * 64, pk_spender="0" * 64, signature="0" * 64)
    coinbase_tx_output = TransactionOutput(value=incentive, hash_pubkey_recipient=miner_address)
    coinbase_tx = Transaction(tx_input=coinbase_tx_input, tx_output=coinbase_tx_output)
    transactions.append(coinbase_tx)

    transactions.append(transaction)

    if transaction.is_valid(blockchain):
        print("\t>> Mining new block")
        nonce = 0
        while True:
            if len(blockchain.blocks) != 0:
                hash_prev_block = blockchain.blocks[len(blockchain.blocks) - 1].get_hash()
                new_block = Block(transactions=transactions, nonce=nonce, prev_block_hash=hash_prev_block)
            else:
                new_block = Block(transactions=transactions, nonce=nonce, prev_block_hash="0" * 64)

            if new_block.get_hash().startswith("0" * blockchain.difficulty):

                prev_transaction = None
                for block in blockchain.blocks:
                    for transaction_blockchain in block.transactions:
                        transaction_hash = transaction_blockchain.get_hash()
                        if transaction_hash == transaction.tx_input.prev_tx:
                            prev_transaction = transaction

                now = datetime.now()
                print("Nonce found:", nonce, "[", now.strftime("%H:%M:%S"), "]")
                result = dict()
                result["new_block"] = new_block
                result["gain"] = coinbase_tx.tx_output.value + (
                            prev_transaction.tx_output.value - transaction.tx_output.value)
                result["status"] = True
                return result

            nonce += 1
    else:
        result = dict()
        result["new_block"] = None
        result["gain"] = 0
        result["status"] = False
        return result


