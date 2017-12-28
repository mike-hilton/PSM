import json
import base64
import binascii
import yaml
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box

"""
PSM - Pretty Secure Messaging
Version: 0.6

Metadata such as sender ID, receiver ID, and labels will not be encrypted - only the payload data will be encrypted.
PSM messages are intended to be sent over encrypted channel, for example using TLS. 
PSM relies on NaCl for all cryptographic operations. 
NaCl uses Curve25519 for public and private key generation and Salsa20 stream cipher for encryption with Poly1305 MAC authentication.
"""

class PSM(object):
  def __init__(self, privateKey=None, publicKey=None, id=None, preserve_sharedKey=True):
    if id == None:
      id = binascii.hexlify(nacl.utils.random(12))
    self.id = id
    self.peers = {}
    self.servers = {}
    self.sharedKeys = {}
    self.preserve_sharedKey = preserve_sharedKey

    if privateKey == None and publicKey == None:
      self.privateKey_nacl = PrivateKey.generate()
      self.publicKey_nacl = self.privateKey_nacl.public_key
      self.privateKey_string = self.privateKey_nacl.encode()
      self.publicKey_string = self.publicKey_nacl.encode()
    else:
      self.privateKey_nacl = nacl.public.PrivateKey(privateKey)
      self.publicKey_nacl = nacl.public.PublicKey(publicKey)
      self.privateKey_string = privateKey
      self.publicKey_string = publicKey

  def add_peer(self, publicKey=None, id=None):
    """
    Takes a peer's (string) public key and (string) id and saves that plus NaCl encoded public key in dict
    """
    if publicKey == None or id == None:
      return "Error"
    self.peers[id] = {"nacl": nacl.public.PublicKey(publicKey), "string": publicKey}
	
  def add_server(self, publicKey=None, id=None):
    """
    Takes a server's (string) public key and (string) id and saves that plus NaCl encoded public key in dict
    It also adds the server to self.peers
    """
    if publicKey == None or id == None:
      return "Error"
    self.servers[id] = {"nacl": nacl.public.PublicKey(publicKey), "string": publicKey}
    self.peers[id] = self.servers[id]

  def add_sharedKey(self, sharedKey=None, label=""):
    """
    WARNING: The chosen label name will be transmitted in clear text
    Takes a Hex encoded shared secret key and a label
    If no secret key is provided, one will be generated
    """
    if label in self.sharedKeys and self.preserve_sharedKey:
      raise Exception("Due to current setting exisiting shared keys can not be overwritten")
    else:
      if sharedKey == None:
        sharedKey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE).encode("hex")
      self.sharedKeys[label] = sharedKey

  def get_sharedKey(self, label=""):
    try:
      return self.sharedKeys[label]
    except Exception as e:
      raise Exception("No sharedKey with label: %s" % label)
      return None

  def secretkey_encrypt_message(self, message="", label=""):
    """
    Takes (string) label and (string) message and optional a (string) category class
    Encrypts the message with the symmetric key
    Returns a dict as Base64 encoded json string containen the encrypted data and the shared key label encrypted
    by the shared key {"data": "KwiffnwOF289r28fj2", "label": "client", "sender": "fokewof"}
    """
    message_box = {"sender": self.id, "type": "sec", "label": label}
    box = nacl.secret.SecretBox(self.sharedKeys[label].decode("hex"))
    try:
      encrypted = base64.b64encode(box.encrypt(bytes(message)))	
    except nacl.exceptions.CryptoError as e:
      print str(e)
      return ""
    message_box["data"] = encrypted
    message_box_b64 = base64.urlsafe_b64encode(json.dumps(message_box))
    return message_box_b64

  def publickey_encrypt_message(self, receivers=[], message="", category=None):
    """
    Takes receivers (array) IDs and (string) message and optional a (string) category class
    Creates a symmetric key with which it encrypt the messsage, the symmetric key is encrypted
    using the receivers publik keys
    Returns a dict as Base64 encoded json string containing the encrypted data and its encryption key encrypted by 
    the receivers public key {"data": "KwiffnwOF289r28fj2", "sender": fokewof", "id1":"kof32", "id2":"gjro3", etc...}
    """
    message_box = {"sender": self.id, "type": "pub"}
    receiver_box = {}
    if category == "servers":
      for server in self.servers:
        receiver_box[server] = self.servers[server]
    else:
      for receiver in receivers:
        receiver_box[receiver] = self.peers[receiver]

    main_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    for receiver in receiver_box:
      box = Box(self.privateKey_nacl, receiver_box[receiver]["nacl"])
      encrypted_key = base64.b64encode(box.encrypt(bytes(main_key)))
      message_box[receiver] = encrypted_key	

    box = nacl.secret.SecretBox(main_key)
    try:
      encrypted = base64.b64encode(box.encrypt(bytes(message)))
    except nacl.exceptions.CryptoError as e:
      print str(e)
      return ""

    message_box["data"] = encrypted
    message_box_b64 = base64.urlsafe_b64encode(json.dumps(message_box))
    return message_box_b64

  def decrypt_message(self, message):
    """
    Takes a urlsafe Base64 decoded dict
    Returns (string) decrypted data
    """
    message_dict = json.loads(base64.urlsafe_b64decode(message))
    if message_dict["type"] == "pub":
      sender_publicKey_nacl = self.peers[message_dict["sender"]]["nacl"]
      asymmetric_box = Box(self.privateKey_nacl, sender_publicKey_nacl)
      main_key = asymmetric_box.decrypt(base64.b64decode(message_dict[self.id]))
      symmetric_box = nacl.secret.SecretBox(main_key)
      plaintext = symmetric_box.decrypt(base64.b64decode(message_dict["data"]))
      return plaintext	

    elif message_dict["type"] == "sec":
      if not self.sharedKeys[message_dict["label"]]:
        raise Exception("Missing sharedKey with label %s" % message_dict["label"])
        return ""
    asymmetric_box = nacl.secret.SecretBox(self.sharedKeys[message_dict["label"]].decode("hex"))
    plaintext = asymmetric_box.decrypt(base64.b64decode(message_dict["data"]))
    return plaintext

def load_config(path):
  """
  Loads config, takes a path to a yaml config file
  """
  def decode_key(key):
    return key.decode("hex")

  try:
    with open(path, "r") as config_file:
      config = yaml.load(config_file)
  except:
    print "Could not find/open/parse file %s" % path
    return None

  if "settings" in config:
    id = config["settings"]["id"]
    privateKey = decode_key(config["settings"]["privateKey"])
    publicKey = decode_key(config["settings"]["publicKey"])
    identity = PSM(privateKey, publicKey, id)
  else:
    identity = PSM()

  if "peers" in config:
    for key, peer in config["peers"].iteritems():
      publicKey = decode_key(peer["publicKey"])
      identity.add_peer(publicKey, peer["id"])

  if "sharedKeys" in config:
    for label, key in config["sharedKeys"].iteritems():
      identity.add_sharedKey(key, label)

  return identity
