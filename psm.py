import json
import base64
import binascii
import yaml
import os
import random
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box

"""
PSM - Pretty Secure Messaging
Version: 0.7

PSM messages are intended to be sent over encrypted channel, for example using TLS. 
PSM relies on NaCl for all cryptographic operations. 
NaCl uses Curve25519 for public and private key generation and Salsa20 stream cipher for encryption with Poly1305 MAC authentication.

WARNING:
  - Metadata such as sender ID, receiver ID, and labels will not be encrypted - only the payload data will be encrypted.
  - Currently vulnerable to certain replay attacks (an attacker could save the first message you send to a certain user, and send it to that user again after the user has restarted the program, i.e re-setted the counter).
"""

class PSM(object):
  def __init__(self, privateKey=None, publicKey=None, id=None, preserve_sharedKey=True, use_counter=True):
    if id == None:
      id = binascii.hexlify(nacl.utils.random(12))
    self.id = id
    self.peers = {}
    self.servers = {}
    self.sharedKeys = {}
    self.preserve_sharedKey = preserve_sharedKey
    self.use_counter = use_counter
    if self.use_counter:
      self.counters = {}
      self.max_counter = 999999999999

    if privateKey == None or publicKey == None:
      self.privateKey_nacl = PrivateKey.generate()
      self.publicKey_nacl = self.privateKey_nacl.public_key
      self.privateKey_string = self.privateKey_nacl.encode(encoder=nacl.encoding.HexEncoder)
      self.publicKey_string = self.publicKey_nacl.encode(encoder=nacl.encoding.HexEncoder)
    else:
      self.privateKey_nacl = nacl.public.PrivateKey(privateKey)
      self.publicKey_nacl = nacl.public.PublicKey(publicKey)
      self.privateKey_string = privateKey
      self.publicKey_string = publicKey

  def get_counter(self, receivers):
    if self.use_counter == False:
      return 0
    receivers.sort()
    key = receivers + ["_"+self.id]
    key_string = "".join(key)
    try:
      current_counter = self.counters[key_string]
    except KeyError:
      random.seed(os.urandom(16))
      counter = random.randint(0, self.max_counter)
    else:
      if counter == self.max_counter:
        counter = 0
      else:
        counter = current_counter + 1
    return "%012d" % counter

  def verify_counter(self, str_counter, receivers, sender):
    if self.use_counter == False:
      return True
    receivers.sort()
    receivers.append("_"+sender)
    key_string = "".join(receivers)
    try:
      counter = int(str_counter)
      previous_counter = self.counters[key_string]
    except ValueError:
      print "Error parsing counter"
      return False
    except KeyError:
      print "[INFO] Initiated new counter for sender: %s" % sender
      self.counters[key_string] = counter
      return True
    else:
      if counter == 0 and previous_counter == self.max_counter:
        return True
      elif counter == (previous_counter + 1):
        return True
      else:
        print "[WARNING] Counter is not correct - could be an attempted replay attack!"
        return False

  def parse_payload(self, data):
    if self.use_counter == False:
      return 0, data
    counter = data[0:12]
    payload = data[12:]
    return counter, payload

  def create_payload(self, data, receiver):
    if self.use_counter == False:
      return data

    if type(receiver) == list:
      counter = self.get_counter(receiver)
      return counter + data
    else:
      raise Exception("[ERROR] Receiver has to be of type list")
      return None

  def add_peer(self, publicKey=None, id=None):
    """
    Takes a peer's (hex) public key and (string) id and saves that plus NaCl encoded public key in dict
    """
    if publicKey == None or id == None:
      return "Error"
    self.peers[id] = {"nacl": nacl.public.PublicKey(publicKey.decode("hex")), "string": publicKey}
	
  def add_server(self, publicKey=None, id=None):
    """
    Takes a server's (hex) public key and (string) id and saves that plus NaCl encoded public key in dict
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
      print "Due to current setting exisiting shared keys can not be overwritten"
    else:
      if sharedKey == None:
        sharedKey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE).encode("hex")
      self.sharedKeys[label] = sharedKey

  def get_sharedKey(self, label=""):
    try:
      return self.sharedKeys[label]
    except Exception as e:
      print "No sharedKey with label: %s" % label
      return None

  def secretkey_encrypt_message(self, message="", label=""):
    """
    Takes a (string) label and a (string) message
    Encrypts the message with the labels symmetric key
    Returns a dict as Base64 encoded json string containen the encrypted data and the shared key label encrypted
    by the shared key {"data": "KwiffnwOF289r28fj2", "label": "client", "sender": "fokewof"}
    """
    message_box = {"sender": self.id, "type": "sec", "label": label}
    box = nacl.secret.SecretBox(self.sharedKeys[label].decode("hex"))
    try:
      payload = self.create_payload(message, [label])
      encrypted = base64.b64encode(box.encrypt(bytes(payload)))
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
    the receivers public key {"data": "KwiffnwOF289r28fj2", "sender": fokewof", destination: {"376c692faafd90f33f9adc7d":"5X32+J++nwIR8jChl01VlLBiYKpTvjyaJaq/fS9/Na1/FAp+ZbavUt0ZbAbVKuZYFsQJZmgqLQL6b11d3CJUBlRYRwmh7QjB", etc...}}
    """
    message_box = {"sender": self.id, "type": "pub", "destination": {}}
    destination = {}
    if category == "servers":
      for server in self.servers:
        destination[server] = self.servers[server]
    else:
      for receiver in receivers:
        destination[receiver] = self.peers[receiver]

    main_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    for receiver in destination:
      box = Box(self.privateKey_nacl, destination[receiver]["nacl"])
      encrypted_key = base64.b64encode(box.encrypt(bytes(main_key)))
      message_box["destination"][receiver] = encrypted_key	

    box = nacl.secret.SecretBox(main_key)
    try:
      payload = self.create_payload(message, receivers)
      encrypted = base64.b64encode(box.encrypt(bytes(payload)))
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
      main_key = asymmetric_box.decrypt(base64.b64decode(message_dict["destination"][self.id]))
      symmetric_box = nacl.secret.SecretBox(main_key)
      plaintext = symmetric_box.decrypt(base64.b64decode(message_dict["data"]))
      counter, payload = self.parse_payload(plaintext)
      receivers = message_dict["destination"].keys()
      if self.verify_counter(counter, receivers, message_dict["sender"]):
        return payload
      else:
        return None

    elif message_dict["type"] == "sec":
      if not self.sharedKeys[message_dict["label"]]:
        print "Missing sharedKey with label %s" % message_dict["label"]
        return ""
    asymmetric_box = nacl.secret.SecretBox(self.sharedKeys[message_dict["label"]].decode("hex"))
    plaintext = asymmetric_box.decrypt(base64.b64decode(message_dict["data"]))
    counter, payload = self.parse_payload(plaintext)
    if self.verify_counter(counter, [message_dict["label"]], message_dict["sender"]):
      return payload
    else:
      return None

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
