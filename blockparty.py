import base64
import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

from Crypto import Random
from Crypto.PublicKey import RSA
import requests
from flask import Flask, jsonify, request


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.private_key = self.create_private_key()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            # Ensure that we are using the complexity for the previous block length
            complexity = self.proof_complexity()
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash, complexity):
                return False

            last_block = block
            current_index += 1

        return True

    def create_private_key(self):
        """Returns a randomly generated private key file"""
        rand = Random.new().read
        private_key = RSA.generate(1024, rand)
        # Can use private_key.exportKey() to obtain actual private key
        # Printing out private key for development purposes
        # print(private_key.exportKey())
        return private_key
        

    def verify_transaction(self, public_key, signature, generated_hash):
        """ Attemps to decode the encoded_msg with the provided public key """
        pk = RSA.importKey(public_key)        
        pk.verify(hash, )


    def new_transaction(self, sender, public_key, recipient, amount, signature):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Sender is the sha512 hexidecimal hash of the public key
        :param public_key: the text of the public key
        :param recipient: Address of the Recipient
        :param amount: Amount
        :param signature: hash of str({'sender': sender, 'recipient': recipient, 'amount': amount})
        :return: The index of the Block that will hold this transaction
        """
        try:
            sig = json.loads(signature)
        except (json.JSONDecodeError, TypeError):
            sig = signature
        
        verified = False
        msg = json.dumps({'sender': sender, 'recipient': recipient, 'amount': amount})
        generated_hash = hashlib.md5(msg.encode()).digest()
        try:
                pk = RSA.importKey(public_key)
                verified = pk.verify(generated_hash, sig)
                #print(generated_hash, sig, public_key)
        except Exception:
            raise Exception('something went wrong')
        
        if not verified:
             raise Exception('NOT ABLE TO VERIFY TRANSACTION')
        
        # Sender is the sha512 hash of the public key
        # sender = hashlib.sha512(decoded_pk.encode()).hexdigest()

        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'hash_public_key': public_key
        })

        return self.chain[-1]['index'] + 1


    def proof_complexity(self):
        """ 
        Implements complexity for the proof of work such that
        for the blockhain reaching a size that divisible by a BASE value raised to 
        the power of x, increase the DEFAULT complexity of the search for leading 0's by
        that amount 
        """
        DEFAULT = 4
        BASE = 25
        n = len(self.chain)
        for x in range(BASE, 0, -1):
            if n // (BASE ** x) != 0:
                return x + DEFAULT
        return DEFAULT


    def proof_of_work(self, last_block):
        """
        Looks for leading zeroes based on the logic inside
        self.proof_complexity() which will increase in complexity as
        more cryptocurrency is mined
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)
        complexity = self.proof_complexity()

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash, complexity) is False:
            proof += 1

        print(proof)

        return proof


    @staticmethod
    def valid_proof(last_proof, proof, last_hash, complexity):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :param complexity: <int> The level of complexity to guess
        :return: <bool> True if correct, False if not.
        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha512(guess).hexdigest()

        return guess_hash[:complexity] == "0" * complexity

    ## Node specific code

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        # right now it just looks for a response back from /hello,
        # we should tighten this up since we are getting back an identifier
        # additionally we should pass in THIS node's hostname/ip and port as part of the request
        # to properly add this node to the new node we want to register 

        if parsed_url.netloc and requests.get(f'http://{parsed_url.netloc}/hello'):
            self.nodes.add(parsed_url.netloc)
        # Accepts an URL without scheme like '192.168.0.5:5000'.
        elif parsed_url.path and requests.get(f'http://{parsed_url.path}/hello'):
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbors = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbors:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                ###
                print(self.valid_chain(chain))
                ###

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False



# Instantiate the SINGLE node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/hello', methods=['GET'])
def hello():
    """Says hello to a fellow node with its identifier on the blockchain"""
    public_key = blockchain.private_key.publickey().exportKey()
    decoded_pk = public_key.decode('utf-8')
    # Sender is the sha512 hash of the public key
    sender = hashlib.sha512(decoded_pk.encode()).hexdigest()
    return sender, 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    proof = blockchain.proof_of_work(last_block)

    public_key = blockchain.private_key.publickey().exportKey()
    decoded_pk = public_key.decode('utf-8')
    # Sender is the sha512 hash of the public key
    sender = hashlib.sha512(decoded_pk.encode()).hexdigest()


    # Sign the mined coin with our node's private key
    msg = json.dumps({'sender': sender, 'recipient': node_identifier, 'amount': 1})
    generated_hash = hashlib.md5(msg.encode()).digest()
    sig = blockchain.private_key.sign(generated_hash, '')

    # The node will receive a reward for finding the proof
    blockchain.new_transaction(
        sender=sender,
        public_key=decoded_pk,
        recipient=node_identifier,
        amount=1,
        signature=sig,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount', 'public_key', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(
        values['sender'], 
        values['public_key'], 
        values['recipient'], 
        values['amount'], 
        values['signature'],
    )

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

## Node specific endpoints

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    try:
        for node in nodes:
            blockchain.register_node(node)
        
        response = {
            'message': 'New nodes have been added',
            'total_nodes': list(blockchain.nodes),
        }
        return jsonify(response), 201
    except requests.exceptions.ConnectionError as err:
        response = {
            'message': f'Error in registering one or more nodes: {err}'
        }
        return jsonify(response), 400
    


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
