import hashlib


class Blockchain:
    def __init__(self, difficulty, blocks=[]):
        self.blocks = blocks
        self.difficulty = difficulty

        first_transaction = Transaction(0, 0)
        genesis_block = mine_block(first_transaction, self)
        self.add_block(genesis_block)

    def add_block(self, block):
        if block.get_hash().startswith("0" * self.difficulty):
            self.blocks.append(block)


class Block:
    def __init__(self, transaction, nonce, prev_block_hash):
        self.transaction = transaction
        self.nonce = nonce
        self.prev_block_hash = prev_block_hash

    def get_hash(self):
        dictionary = self.__dict__.copy()
        dictionary['transaction'] = self.transaction.__dict__
        block_str = str(dictionary)

        hash_manager = hashlib.sha256()
        hash_manager.update(bytes(block_str, encoding='utf-8'))
        return hash_manager.hexdigest()


class Transaction:
    def __init__(self, input, output):
        self.input = input
        self.output = output


def mine_block(transaction, blockchain):
    nonce = 0
    while True:
        if len(blockchain.blocks) != 0:
            hash_prev_block = blockchain.blocks[len(blockchain.blocks) - 1].get_hash()
            new_block = Block(transaction, nonce, hash_prev_block)
        else:
            new_block = Block(transaction, nonce, "")

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
