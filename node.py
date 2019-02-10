from datetime import date

from ecdsa import SigningKey, SECP256k1
from gevent.monkey import patch_all
patch_all()
from uuid import uuid4

import datetime as date
import logging
import requests
import gevent
import time
import random
import threading
from threading import Thread
from blockchain import Block, BlockChain, SigningBlock, UploadBlock, ReadBlock
from flask import Flask, jsonify, url_for, request
from gevent.pywsgi import WSGIServer
from copy import deepcopy
from typing import List

# app.run from Flask had weird side effects with running multiple apps at the same time
# As we are already using gevent. Use the builtin WSGIServer which is handling this fine

log = logging.getLogger(__package__)
MASTER_PORT = 5000


class Node(object):
    """
    Represents a Blockchain node in the Network
    """
    def __init__(self, host, port, genesis, master_node):
        self.host = host
        self.port = port
        self.app = Flask(__name__ + str(port))  # Must be unique?
        self.blockchain = deepcopy(genesis)  # type: BlockChain
        self.buffer = []  # type: List[Block]
        self._http_server_greenlet = None
        self.master_node = master_node  # type: MasterNode
        self.lock = threading.Lock()
        if self.master_node is not None:
            self.master_node.add_slave(self)

    # Add block for signing event
    def add_signing_block(self, filename, sig, sign, val_status, signer, signed_event_hash):
        this_timestamp = date.datetime.now()
        signing_block = SigningBlock(None, this_timestamp, sign, val_status, None, filename, sig, signer, signed_event_hash)
        self.buffer.append(signing_block)

    def find_event_and_sign(self, hashvalue, signer, signing_key):
        sk = signing_key
        vk = sk.get_verifying_key()
        sign_block = self.find_most_recent_sign_block_for_event(hashvalue)
        if sign_block is not None: # file has been signed before
            print("PREVIOUS SIGN BLOCK FOUND")
            hashvalue = bytes(hashvalue, encoding='utf-8')
            filename = sign_block.filename
            sig = sk.sign(hashvalue)
            req_signers_left = sign_block.signers.copy()
            if vk.verify(sig, hashvalue):
                self.add_signing_event_to_chain(filename, req_signers_left, sig, signer, hashvalue)
            else:
                print("SIGNATURE FALSE!!!!111")
        else: # file has not been signed before
            for x in range(0, len(self.blockchain.block_array)):
                if self.blockchain.block_array[x].hash == hashvalue:
                    hashvalue = bytes(hashvalue, encoding='utf-8')
                    filename = self.blockchain.block_array[x].uploaded_file.filename
                    sig = sk.sign(hashvalue)
                    original_signers = self.blockchain.block_array[x].signers.copy()
                    if vk.verify(sig, hashvalue):
                        self.add_signing_event_to_chain(filename, original_signers, sig, signer, hashvalue)
                    else:
                        print("SIGNATURE FALSE!!!!111")

    def find_most_recent_sign_block_for_event(self, hashvalue):
        most_recent_sign_block = None
        for x in range(len(self.blockchain.block_array) - 1, -1, -1):
            if isinstance(self.blockchain.block_array[x], SigningBlock):
                print("signed_event_hash of this block: " + str(self.blockchain.block_array[x].signed_event_hash))
                print("desired hash: " + str(hashvalue))
                conv_hash = bytes(hashvalue, encoding='utf-8')
                print("converted desired hash:" + str(conv_hash))
                if self.blockchain.block_array[x].signed_event_hash == bytes(hashvalue, encoding='utf-8'):
                    most_recent_sign_block = self.blockchain.block_array[x]
        return most_recent_sign_block

    def add_signing_event_to_chain(self, filename, original_signers, sig, signer, hashvalue):
        if signer in original_signers:
            original_signers.remove(signer)
        print("ADD SIGNING EVENT TO CHAIN")

        self.add_signing_block(filename, sig, original_signers, self.check_if_all_required_signers_have_signed(original_signers), signer, hashvalue)

    def check_if_all_required_signers_have_signed(self, original_signers):
        if not original_signers:
            # verify signatures
            return "VALIDATED by all required signers"
        else:
            return "WAITING for at least one signer"

    # Add block for uploading of a file
    def add_upload_block(self, uploaded_file, sign, val_status, uploader):
        with self.lock:
            this_timestamp = date.datetime.now()
            upload_block = UploadBlock(None, this_timestamp, sign, val_status, None, uploaded_file, uploader)
            self.buffer.append(upload_block)

    def find_event_and_add_read_block(self, hashvalue, reader):
        for x in range(0, len(self.blockchain.block_array)):
            if self.blockchain.block_array[x].hash == hashvalue:
                hashvalue = bytes(hashvalue, encoding='utf-8')
                filename = self.blockchain.block_array[x].uploaded_file.filename
                self.add_read_block(filename, reader, "n.a.")

    # Add block when a file is downloaded
    def add_read_block(self, read_file, reader, sign):
        with self.lock:
            this_timestamp = date.datetime.now()
            this_val_status = "n.a."
            read_block = ReadBlock(None, this_timestamp, sign, this_val_status, None, read_file, reader)
            self.buffer.append(read_block)

    def node_address(self):
        return "http://{}:{}/".format(self.host, self.port)

    def register_node(self, addr, announce=True):
        log.info("{} :: registering node {}".format(self.node_address(), addr))
        self.blockchain.create_node(addr)
        if announce:
            # Announce ourself to the other Node
            node_api = NodeAPI(addr)
            node_api.register_node(self.node_address())

    def _http_index(self):
        return "Blockchain Node API {}:{}".format(self.host, self.port)

    def _http_register_node(self):
        node_data = request.get_json()
        node_addr = node_data['address']
        self.register_node(node_addr, announce=False)
        return jsonify({'status': 'OK'})

    def _http_get_chain(self):
        result = {
            'chain': self.blockchain.get_serialized_chain()
        }
        return jsonify(result)

    def _http_server(self):
        self.app.add_url_rule('/', 'index', self._http_index, methods=['GET'])
        self.app.add_url_rule('/register-node', 'register_node', self._http_register_node, methods=['POST'])
        self.app.add_url_rule('/get-chain', 'get_chain', self._http_get_chain, methods=['GET'])
        http_server = WSGIServer((self.host, self.port), self.app)
        http_server.serve_forever()  # Blocks

    def start(self):
        self._http_server_greenlet = gevent.spawn(self._http_server)
        if self.master_node is not None:
            buffer_thread = BufferThread(self.buffer, self.master_node)
            buffer_thread.start()

    def stop(self):
        gevent.kill(self._http_server_greenlet)


class MasterNode(Node):
    def __init__(self, host, port, genesis):
        super(MasterNode, self).__init__(host, port, genesis, None)
        self.slaves = []  # type: List[Node]
        self.lock = threading.Lock()

    def add_slave(self, slave: Node):
        self.slaves.append(slave)

    def add_new_block(self, block: Block):
        with self.lock:
            self.blockchain.add_new_block(block)
            self.update_slaves_with_new_chain()

    def update_slaves_with_new_chain(self):
        print("Updating slave nodes")

        block_chain_copy = deepcopy(self.blockchain.block_array)
        for slave in self.slaves:
            slave.blockchain.block_array = block_chain_copy


class BufferThread(Thread):
    def __init__(self, buffer, master_node: MasterNode):
        super().__init__()
        self.buffer = buffer
        self.master_node = master_node

    def run(self):
        while True:
            time.sleep((random.randint(5, 10))/10)
            if len(self.buffer) > 0:
                print("************Found stuff in buffer*******************")
                self.master_node.add_new_block(self.buffer.pop(0))


class NodeAPI(object):
    """
    Class that is used to talk to other Nodes over their HTTP API
    """
    def __init__(self, node_addr):
        self.node_addr = node_addr

    def register_node(self, node_addr):
        data = {
            'address': node_addr
        }
        requests.post(self.node_addr + '/register-node', json=data).json()

    def get_chain(self):
        return requests.get(self.node_addr + '/get-chain',).json()

def configure_logging(verbose):
    _log = logging.getLogger(__package__)
    console = logging.StreamHandler()
    if verbose:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    console.setFormatter(formatter)
    _log.addHandler(console)
    _log.setLevel(logging.DEBUG)


def main():
    configure_logging(True)

    log.debug("Spawning master node on port {}".format(MASTER_PORT))
    master_node = Node("127.0.0.1", MASTER_PORT)
    master_node.start()
    gevent.sleep(1)  # Allow some time for master node to listen on port

    nodes = []
    print("hallo")
    for i in range(1, 10):
        print("party time")
        port = 5000 + i
        log.debug("Spawning node on port {}".format(port))
        node = Node("127.0.0.1", port)
        node.start()
        node.register_node("http://127.0.0.1:{}".format(MASTER_PORT))
        nodes.append(node)
    print("Nodes: " + str(nodes))
    gevent.wait()

if __name__ == '__main__':
    main()