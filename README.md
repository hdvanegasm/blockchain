# Basic blockchain implementation

In this repository you will find a basic implementation of a blockchain using *Bitcoin: a peer-to-peer electronic cash system* and Bitcoin documentation as a basis.

## Instructions:

* If you want to restore the project directory to a initial state, you must run *utilities/prepare_environment.py*. This file will delete all the public/private key pairs of the system and will delete the file that stores the complete blockchain.

* If you want to execute a client, you must run *client.py* file. If there is not a sharing node, the first execution of this script will run a node that share all the information between nodes. If there is a sharing node, the other clients will connect to him and they will be able to share all the information in a broadcast way.

* If a sharing node disconnects, another client will take his place.

* If you want to run a miner node, you must run *miner.py*. When a node broadcasts a transaction, the miner nodes will mine a new block with the coinbase and the new client's transaction, if the node finishes the mining process, it will broadcast the mined block to all the nodes and they will include the mined block if it is not already mined.

### Available commands:

* **cmd_show_peers:** this command shows all the peers connected to the network in the format (IP, Port).
* **cmd_show_addresses:** this command will show all the addresses of the clients and miners in the network. The addres is a 160-bit hash of the public key of each node. 
* **cmd_gift:** this command will generate a new coin from nothing in order to make experiments with the functionalities of the software. *Note:* in a real environment, this function does not exists; this is for academic uses only.
* **cmd_new_tx:** this command will create a new transaction with the unspent incoming transactions for a client.
