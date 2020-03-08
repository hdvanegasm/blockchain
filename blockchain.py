from Crypto.Hash import SHA256


class Blockchain:

    def __init__(self, difficulty, blocks=[]):
        self.blocks = blocks
        self.difficulty = difficulty

        first_transaction = Transaction(input=50, output=50)
        genesis_block = mine_block(first_transaction, self)
        self.add_block(genesis_block)

    def add_block(self, block):
        if block.get_hash().startswith("0" * self.difficulty):
            self.blocks.append(block)


class Block:

    def __init__(self, transactions, nonce, prev_block_hash):
        self.transactions = transactions
        self.nonce = nonce
        self.prev_block_hash = prev_block_hash

    def get_hash(self):
        block_serialization = self.serialize()
        hash_object = SHA256.new(data=bytes(block_serialization, encoding='utf-8'))
        return hash_object.hexdigest()

    def serialize(self):
        dictionary = self.__dict__.copy()

        transaction_serializations = list()
        for transaction in self.transactions:
            transaction_serializations.append(transaction.serialize())

        dictionary['transactions'] =  transaction_serializations
        block_serialization = str(dictionary)
        return block_serialization


class Transaction:

    def __init__(self, tx_input, tx_output):
        self.tx_input = tx_input
        self.tx_output = tx_output

    def fee(self):
        return self.input - self.output

    # TODO Implement validation of transactions
    def validate(self, blockchain):
        # 1. Fin the prev tx
        # 2. Extract the output of the tx
        # 3. Execute the validation script
        # 4. Return the validation result
        pass

    def serialize(self):
        return str(self.__dict__)

    def get_hash(self):
        tx_serialization = self.serialize()
        hash_object = SHA256.new(data=bytes(tx_serialization, encoding='utf-8'))
        return hash_object.hexdigest()


# TODO Implement transaction input
class TransactionInput:

    def __init__(self, prev_tx, index, signature):
        # Previous Tx is the hash of the previous Tx
        self.prev_tx = prev_tx
        self.index = index
        self.signature = signature


# TODO Implement transaction output
class TransactionOutput:

    def __init__(self, value, hash_pub_key_recipient):
        self.value = value

        # It is the hashed value of the Pk of the recipient
        self.hash_pub_key_recipient = hash_pub_key_recipient


def mine_block(transactions, blockchain):
    nonce = 0
    while True:
        if len(blockchain.blocks) != 0:
            hash_prev_block = blockchain.blocks[len(blockchain.blocks) - 1].get_hash()
            new_block = Block(transaction, nonce, hash_prev_block)
        else:
            new_block = Block(transactions=transactions, nonce=nonce, prev_block_hash="0" * 64)

        if new_block.get_hash().startswith("0" * blockchain.difficulty):
            print("Nonce found:", nonce)
            return new_block

        nonce += 1


if __name__ == "__main__":
    transaction = Transaction(input=31, output=30)
    print(transaction.__dict__)

    # blockchain = Blockchain(difficulty=5)
    #
    # block = mine_block(transaction, blockchain)
    # blockchain.add_block(block)
    #
    # print(block.__dict__)
    # print("Bitcoin earned:", transaction.input - transaction.output)
    #
    # print(len(blockchain.blocks))
