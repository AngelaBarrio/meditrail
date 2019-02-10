import hashlib as hasher
import datetime as date
import timeit
import time
import openpyxl
from openpyxl.utils import get_column_letter
from ecdsa import SigningKey, ecdsa
from ecdsa import SECP256k1
from copy import copy

class Block:
    def __init__(self, index, timestamp, description, signers, validation_status, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.description = description
        self.signers = signers
        self.previous_hash = previous_hash
        self.validation_status = validation_status
        self.hash = self.hash_block()

    def hash_block(self):
        sha = hasher.sha256()
        sha.update(str(self.index).encode('utf-8') + str(self.timestamp).encode('utf-8') + str(self.description).encode(
            'utf-8') + str(self.signers).encode('utf-8') + str(self.validation_status).encode('utf-8') +
                   str(self.previous_hash).encode('utf-8'))
        return sha.hexdigest()

    def to_string(self):
        return "[" + str(self.index) + "] MESSAGE: " + self.description + \
                      "; \n REQUIRED SIGNERS: " + str(self.signers) + \
                      "; \n VALIDATION STATUS: " + self.validation_status + \
                      "; \n TIMESTAMP: " + str(self.timestamp) + \
                      "; \n PREVIOUS HASH: " + str(self.previous_hash) + \
                      "; \n HASH: " + str(self.hash) + "; \n \n"

class UploadBlock(Block):
    def __init__(self, index, timestamp, signers, validation_status, previous_hash, uploaded_file, uploader):
        description = uploaded_file.filename + " has been uploaded by " + uploader
        time.sleep(1/100)
        super(UploadBlock, self).__init__(index, timestamp, description, signers, validation_status, previous_hash)
        self.uploaded_file = uploaded_file

    def __deepcopy__(self, original):
        #This is a shallow copy, but that is fine for this class
        return copy(self)


class SigningBlock(Block):
    def __init__(self, index, timestamp, signers, validation_status, previous_hash, filename, signature, signer, signed_event_hash):
        description = "File " + str(filename) + " has been signed by " + signer
        time.sleep(1/100)
        super(SigningBlock, self).__init__(index, timestamp, description, signers, validation_status, previous_hash)
        self.signed_event_hash = signed_event_hash
        self.signature = signature
        self.filename = filename


class ReadBlock(Block):
    def __init__(self, index, timestamp, signers, validation_status, previous_hash, read_file, reader):
        description = "File " + str(read_file) + " has been accessed by " + reader
        time.sleep(1/100)
        super(ReadBlock, self).__init__(index, timestamp, description, signers, validation_status, previous_hash)
        self.read_file = read_file
        self.reader = reader
        print("hallo ik ben hier")


class BlockChain:

    def __init__(self):
        self.nodes = set()
        self.block_array = [self.create_genesis_block()]

    def create_node(self, address) -> bool:
        self.nodes.add(address)
        return True

    # Generate genesis block
    def create_genesis_block(self) -> Block:
        # Manually construct a block with
        # index zero and arbitrary previous hash
        genesis_block = Block(0, date.datetime.now(), "Genesis Block", [], "No validation required", "0")
        with open("records.txt", "a") as text_file:
            text_file.write(genesis_block.to_string())
        return genesis_block

    # Add block when a file is downloaded
    def add_read_block(self, read_file, reader, sign):
        last_block = self.block_array[-1]
        this_index = len(self.block_array)
        this_timestamp = date.datetime.now()
        this_hash = last_block.hash
        this_val_status = "n.a."

        read_block = ReadBlock(this_index, this_timestamp, sign, this_val_status, this_hash, read_file, reader)
        self.block_array.append(read_block)
        with open("records.txt", "a") as text_file:
            text_file.write(read_block.to_string())

    def add_new_block(self, received_block: Block):
        print("A block was received")
        received_block.index = len(self.block_array)
        received_block.previous_hash = self.block_array[-1].hash
        self.block_array.append(received_block)
        with open("records.txt", "a") as text_file:
            text_file.write(received_block.to_string())

        #excel_document = openpyxl.load_workbook('sample.xlsx')
        #sheet = excel_document.active
        now = timeit.default_timer()
        #sheet.append([now])
        #excel_document.save("sample.xlsx")
        print("block added at: " + str(now))

    # Print blockchain
    def print_chain(self):
        print(self.blockchain_to_string())

    def blockchain_to_string(self):
        init_string = "Our blockchain consists of: \n"
        for x in range(0, len(self.block_array)):
            current_block = self.block_array[x]
            init_string = init_string + current_block.to_string()
        return init_string

    def find_event_and_add_read_block(self, hashvalue, reader):
        for x in range(0, len(self.block_array)):
            if self.block_array[x].hash == hashvalue:
                hashvalue = bytes(hashvalue, encoding='utf-8')
                filename = self.block_array[x].uploaded_file
                self.add_read_block(filename, reader, "n.a.")
