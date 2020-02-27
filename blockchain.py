import hashlib
import time

class Blockchain:
    def __init__(self, difficulty, blocks = []):
        first_transaction = Transaction("a988a7d0a8dd8")
        genesis_block = Block(first_transaction, 0, "")
        blocks.append(genesis_block)

        self.blocks = blocks
        self.difficulty = difficulty

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
    def __init__(self, hash_code):
        self.hash_code = hash_code

def mine_block(transaction, blockchain):
    nonce = 0
    while True:
        hash_prev_block = blockchain.blocks[len(blockchain.blocks) - 1].get_hash()
        new_block = Block(transaction, nonce, hash_prev_block)

        if new_block.get_hash().startswith("0" * blockchain.difficulty):
            print("Hash new block:", new_block.get_hash())
            print("New block:", new_block.__dict__)
            print("Nonce found:", nonce)
            return new_block

        nonce += 1

if __name__ == "__main__":
    transaccion = Transaction("skfsjdglkjfn")
    blockchain = Blockchain(difficulty = 6)

    initial_time = time.time()
    block = mine_block(transaccion, blockchain)
    time_spent = time.time() - initial_time

    print("Time required:", time_spent, "seconds")

    blockchain.add_block(block)

    print(len(blockchain.blocks))