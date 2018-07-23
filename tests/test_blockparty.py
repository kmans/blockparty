import hashlib
import json
from unittest import TestCase, mock

from blockparty import Blockchain
import requests

class BlockchainTestCase(TestCase):

    def setUp(self):
        self.blockchain = Blockchain()

    def create_block(self, proof=123, previous_hash='abc'):
        self.blockchain.new_block(proof, previous_hash)

    def create_transaction(self):
        sender="3002c6f3ead0346058c08e9288bc8f51176f5ed3d086043666d746221f84094d72501ea2e0b9f0251e9a860eae0a5655149892b3ca7c6d75f1f2847be77ee78b"
        recipient='Bob'
        amount=0.10
        signature = "[42481061034590633900956381972050213539365396451305177937236385827407435560534329095470986817389777242646902230842624122710066337259237493762973943292211858266957109421036442600056690863532186109385749524553599582513060425435152804220045013130635073756983317423194472904188999824951047272169090037192563884905]"
        public_key =  "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo0JKbhQ5Fh4O5Defl57XE1eC5\ne06wxAso45DGulKMVaF1SBZirvKOFA3oSQ3BiOqxBQGmYEzt8GB2l0SEQNWdgJDb\nfDkGr7rhOmP+j6a2p9CiH0z/H8GIjIECg50Di+WzDcgR0d+ICI5yiTXzFsXeJTeV\nhDs1242k5Ux1QDSMOwIDAQAB\n-----END PUBLIC KEY-----"
        self.blockchain.new_transaction(
            sender=sender,
            public_key=public_key,
            recipient=recipient,
            amount=amount,
            signature=signature
        )


class TestRegisterNodes(BlockchainTestCase): 
    @mock.patch.object(requests, 'get')
    def test_valid_nodes(self, mockget):
        resp = mock.Mock()
        mockget.return_value = resp
        
        blockchain = Blockchain()

        blockchain.register_node('http://192.168.0.1:5000')

        self.assertIn('192.168.0.1:5000', blockchain.nodes)

    @mock.patch.object(requests, 'get')
    def test_malformed_nodes(self, mockget):
        resp = mock.Mock()
        mockget.return_value = resp
        blockchain = Blockchain()

        blockchain.register_node('http//192.168.0.1:5000')

        self.assertNotIn('192.168.0.1:5000', blockchain.nodes)

    @mock.patch.object(requests, 'get')
    def test_idempotency(self, mockget):
        resp = mock.Mock()
        mockget.return_value = resp
        blockchain = Blockchain()

        blockchain.register_node('http://192.168.0.1:5000')
        blockchain.register_node('http://192.168.0.1:5000')

        assert len(blockchain.nodes) == 1


class TestBlocksAndTransactions(BlockchainTestCase):

    def test_block_creation(self):
        self.create_block()

        latest_block = self.blockchain.chain[-1]

        # The genesis block is create at initialization, so the length should be 2
        assert len(self.blockchain.chain) == 2
        assert latest_block['index'] == 2
        assert latest_block['timestamp'] is not None
        assert latest_block['proof'] == 123
        assert latest_block['previous_hash'] == 'abc'

    def test_create_transaction(self):
        self.create_transaction()

        transaction = self.blockchain.current_transactions[-1]

        assert transaction

        assert transaction['sender'] == "3002c6f3ead0346058c08e9288bc8f51176f5ed3d086043666d746221f84094d72501ea2e0b9f0251e9a860eae0a5655149892b3ca7c6d75f1f2847be77ee78b"
        assert transaction['recipient'] == 'Bob'
        assert transaction['amount'] == 0.10

    def test_block_resets_transactions(self):
        self.create_transaction()

        initial_length = len(self.blockchain.current_transactions)

        self.create_block()

        current_length = len(self.blockchain.current_transactions)

        assert initial_length == 1
        assert current_length == 0

    def test_return_last_block(self):
        self.create_block()

        created_block = self.blockchain.chain[-1]

        assert len(self.blockchain.chain) == 2
        assert created_block is self.blockchain.chain[-1]


class TestHashingAndProofs(BlockchainTestCase):

    def test_hash_is_correct(self):
        self.create_block()

        new_block = self.blockchain.chain[-1]
        new_block_json = json.dumps(self.blockchain.chain[-1], sort_keys=True).encode()
        new_hash = hashlib.sha256(new_block_json).hexdigest()

        assert len(new_hash) == 64
        assert new_hash == self.blockchain.hash(new_block)
