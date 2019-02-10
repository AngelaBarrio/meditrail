import argparse
import json
import os
import gevent
import timeit
import openpyxl
from ecdsa import SECP256k1
from ecdsa import SigningKey
from flask import Flask, render_template, request, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from gevent.pywsgi import WSGIServer
from werkzeug.utils import secure_filename
from copy import deepcopy

from blockchain import UploadBlock, BlockChain
from node import Node, MasterNode

node = Flask(__name__)
os.makedirs(os.path.join(node.static_folder, 'uploads'), exist_ok=True)
file = open("records.txt", "w").close()
peer_nodes = {}


login_manager = LoginManager()
login_manager.init_app(node)

walgelijk = 0


class User(UserMixin):

    def __init__(self, id):
        self.id = id
        self.name = "user" + str(id)
        self.password = self.name + "_secret"
        self.private_key = SigningKey.generate(curve=SECP256k1)

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)


# create some users with ids 1 to 20
users = [User(userId) for userId in range(1, 31)]


genesis = BlockChain()
print("Creating master node at 9999")
master_node = MasterNode("127.0.0.1", 9999, genesis)
master_node.start()

# assign port numbers to user ids
usersToNodes = {}  # type: Dict[int, Node]
for u in users:
    port = 5000 + u.id
    print("Creating user node at " + str(port))
    user_node = Node("127.0.0.1", port, genesis, master_node)
    user_node.start()
    usersToNodes[u.id] = user_node


def get_user_by_username(user_name):
    for user in users:
        if user.name == user_name:
            return user
    return None


@login_manager.user_loader
def load_user(user_id):
    print("Load user")
    for user in users:
        if str(user.id) == str(user_id):
            return user
    return None


def sign_thing():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    sig = sk.sign(b"message")
    print("Signature: " + str(sig))
    vk.verify(sig, b"message")  # True


def check_if_all_required_signers_have_signed(original_signers):
    if not original_signers:
        # verify signatures
        return "VALIDATED by all required signers"
    else:
        return "WAITING for at least one signer"


def check_if_val_is_needed(original_signers):
    if not original_signers:
        return "No validation required"
    else:
        return "WAITING for at least one signer"

@node.route('/home')
def home():
    if current_user.is_anonymous:
       return render_template('login.html')
    else:
        return render_template('home.html')

@node.route('/login', methods=['POST'])
def do_admin_login():
    user = get_user_by_username(request.form['username'])
    if (user is None) or (user.password != request.form['password']):
        flash('wrong user or password!')
    else:
        login_user(user)
        print(current_user.name)
    return home()

@node.route("/logout")
@login_required
def logout():
    logout_user()
    return home()

@node.route('/me', methods=['GET'])
@login_required
def me():
    return "Welcome, %s" % current_user.name, 200


@node.route('/logs')
@login_required
def content():
    block_strings = map(lambda block: block.to_string(), get_block_chain_node().blockchain.block_array)
    return render_template('logs.html', text="".join(block_strings))


@node.route('/debug', methods=['GET'])
@login_required
def list_log():
    get_block_chain_node().print_chain()
    return "woot", 200


@node.route('/uploader', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join(node.static_folder, 'uploads', secure_filename(file.filename)))
        global walgelijk
        if walgelijk == 1:
            for i in range(0, 200):
                signers = request.form.getlist('box')
                chain_node = get_block_chain_node()
                chain_node.add_upload_block(file, signers, check_if_val_is_needed(signers), current_user.name)
                gain_consensus()
        else:
            signers = request.form.getlist('box')
            chain_node = get_block_chain_node()
            chain_node.add_upload_block(file, signers, check_if_val_is_needed(signers), current_user.name)
            gain_consensus()
        walgelijk = walgelijk + 1

        return render_template('uploaded.html')


@node.route('/signer/<postedhash>', methods=['GET'])
@login_required
def sign(postedhash):
    now = timeit.default_timer()
    print("start signing at: " + str(now))
    #sign_thing()
    get_block_chain_node().find_event_and_sign(postedhash, current_user.name, current_user.private_key)
    return render_template('signed.html')


@node.route('/readfile/<postedhash>', methods=['GET'])
@login_required
def readfile(postedhash):
    get_block_chain_node().find_event_and_add_read_block(postedhash, current_user.name)
    gain_consensus()
    return render_template('home.html')


@node.route('/uploads', methods=['GET'])
@login_required
def list_uploads():
    upload_blocks = []
    for block in get_block_chain_node().blockchain.block_array:
        if isinstance(block, UploadBlock):
            upload_blocks.append(block)

    return render_template('uploads.html', upload_blocks=upload_blocks)


@node.route('/blocks', methods=['GET'])
@login_required
def get_blocks():
  chain_to_send = get_block_chain_node()
  # Convert our blocks into dictionaries
  # so we can send them as json objects later
  for block in chain_to_send:
        block_index = str(block.index)
        block_timestamp = str(block.timestamp)
        block_data = str(block.data)
        block_signers = str(block.signers)
        block_validation_status = str(block.validation_status)
        block_hash = block.hash
        block = {
          "index": block_index,
          "timestamp": block_timestamp,
          "data": block_data,
          "signers": block_signers,
          "validation_status": block_validation_status,
          "hash": block_hash
        }
  chain_to_send = json.dumps(chain_to_send)
  return chain_to_send

def find_new_chains():
  # Get the blockchains of every
  # other node
  other_chains = []
  for node_url in peer_nodes:
    # Get their chains using a GET request
    block = request.get(node_url + "/blocks").content
    # Convert the JSON object to a Python dictionary
    block = json.loads(block)
    other_chains.append(block)
  print (str(other_chains))
  return other_chains


def gain_consensus():

    longest_chain = get_block_chain_node().blockchain.block_array

    for userNode in usersToNodes.values():
        if len(userNode.blockchain.block_array) > len(longest_chain):
            longest_chain = userNode.blockchain.block_array

    get_block_chain_node().blockchain.block_array = deepcopy(longest_chain);


def startup():
    node.secret_key = os.urandom(12)
    try:
        http_server = WSGIServer((args.address, args.port), node)
        http_server.serve_forever()  # Blocks
    except OSError:
        print("Ok!")

def get_block_chain_node() -> Node:
    return usersToNodes.get(current_user.id, None)


if __name__ == '__main__':
    #  GREENLET
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-a", "--address", help="Address of AngelaChain Web server", required=True, default="127.0.0.1")
    parser.add_argument("-p", "--port", required=True, help="Port of AngelaChain web server", default=5000, type=int)
    parser.add_argument("-n", "--node_address", help="Address of AngelaChain Web server", required=True, default="127.0.0.1")
    parser.add_argument("-x", "--node_port", required=True, help="Port of AngelaChain web server", default=5001, type=int)
    args = parser.parse_args()

#actual startup
g = gevent.spawn(startup)
gevent.wait()












