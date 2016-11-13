
# coding: utf-8

# In[167]:

import os
import base64
import binascii
import struct
import requests
import json
import random
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# In[5]:

def rsa_keypair_gen():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pk = sk.public_key()
    return pk, sk
def dsa_keypair_gen():
    sk = dsa.generate_private_key(key_size=1024, backend=default_backend())
    pk = sk.public_key()
    return pk, sk


# In[6]:

def encode_pk(pk_rsa, pk_dsa):
    #1. DER encoding
    pk_rsa_bytes = pk_rsa.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pk_dsa_bytes = pk_dsa.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #2. Base64 encoding
    pk_rsa_bytes_encoded = base64.b64encode(pk_rsa_bytes)
    pk_dsa_bytes_encoded = base64.b64encode(pk_dsa_bytes)
    #3. Concatenation in format: Base64_RSA_PubKey||ASCII(0x25)||Base64_DSA_PubKey
    encoded_string = pk_rsa_bytes_encoded + "\x25" + pk_dsa_bytes_encoded
    return encoded_string
def decode_pk(encoded_string):
    pk_pair = encoded_string.split("%")
    pk_rsa_bytes = base64.b64decode(pk_pair[0])
    pk_dsa_bytes = base64.b64decode(pk_pair[1])
    pk_rsa = serialization.load_der_public_key(pk_rsa_bytes, backend=default_backend())
    pk_dsa = serialization.load_der_public_key(pk_dsa_bytes, backend=default_backend())
    return pk_rsa, pk_dsa


# In[7]:

def rsa_encrypt(pk_rsa, m):
    c = pk_rsa.encrypt(m, padding.PKCS1v15())
    return c
def rsa_decrypt(sk_rsa, c):
    m = sk_rsa.decrypt(c,padding.PKCS1v15())
    return m


# In[109]:

def dsa_sign(sk_dsa, msg):
    signer = sk_dsa.signer(hashes.SHA1())
    signer.update(msg)
    signature = signer.finalize()
    return signature
def dsa_verify(pk_dsa, sig, msg):
    verifier = pk_dsa.verifier(sig, hashes.SHA1())
    verifier.update(msg)
    try:
        verifier.verify()
    except Exception:
        return 0
    return 1


# In[9]:

def aes_encrypt(key, iv, m):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    c = encryptor.update(m) + encryptor.finalize()
    return c
def aes_decrypt(key, iv, c):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    m = decryptor.update(c) + decryptor.finalize()
    return m


# In[10]:

def add_padding(m1):
    n = len(m1)%16
    if n != 0:
        ps = bytes(bytearray([16-n]))*(16-n)
    if n == 0:
        ps = '\x10' * 16
    m2 = m1 + ps
    return m2
def verify_padding(m2):
    n = int(m2[-1].encode('hex'), 16)
    m2_padding = m2[-n:]
    size = len(m2_padding)
    for x in m2_padding:
        if x != bytearray([size]):
            return 0
    return 1
def remove_padding(m2):
    n = int(m2[-1].encode('hex'), 16)
    m1 = m2[:-n]
    return m1


# In[121]:

def encrypt_message(m, pk_rsa_recipient, sk_dsa_sender, sender_userid):
    #1
    aes_key = os.urandom(16)
    #2
    c1 = rsa_encrypt(pk_rsa_recipient, aes_key)
    #3
    m_formatted = sender_userid + "\x3a" + m
    #4
    crc = binascii.crc32(m_formatted) & 0xffffffff
    crc_nw_bytes = struct.pack("!L", crc)
    m_crc = m_formatted + crc_nw_bytes
    #print crc_nw_bytes
    #5
    m_padded = add_padding(m_crc)
    #6
    iv = os.urandom(16)
    #7
    c2 = iv + aes_encrypt(aes_key, iv, m_padded)
    #8
    c1_base64 = base64.b64encode(c1)
    c1_base64_utf8 = c1_base64.encode("utf-8")
    c2_base64 = base64.b64encode(c2)
    c2_base64_utf8 = c2_base64.encode("utf-8")
    #9
    c_without_sig = c1_base64_utf8 + "\x20".encode("utf-8") + c2_base64_utf8
    dsa_sig = dsa_sign(sk_dsa_sender, c_without_sig)
    #print c_without_sig
    #10
    dsa_sig_base64 = base64.b64encode(dsa_sig)
    dsa_sig_base64_utf8 = dsa_sig_base64.encode("utf-8")
    #11
    c = c_without_sig + "\x20".encode("utf-8") + dsa_sig_base64_utf8
    return c
def decrypt_message(c, sk_rsa_recipient, pk_dsa_sender, sender_userid):
    #2
    c_elements = c.split("\x20")
    c1_base64 = c_elements[0]
    c2_base64 = c_elements[1]
    dsa_sig_base64 = c_elements[2]
    #3
    c1 = base64.b64decode(c1_base64)
    c2 = base64.b64decode(c2_base64)
    dsa_sig = base64.b64decode(dsa_sig_base64)
    #4
    c_without_sig_base64 = c1_base64+"\x20"+c2_base64
    #print c_without_sig_base64
    if dsa_verify(pk_dsa_sender, dsa_sig, c_without_sig_base64.encode()) == 0:
        print "Signature verification FAILED."
        return
    #5
    k = rsa_decrypt(sk_rsa_recipient, c1)
    #6
    iv = c2[:16]
    c2_withoutiv = c2[16:]
    m_padded = aes_decrypt(k, iv, c2_withoutiv)
    #7
    if verify_padding(m_padded) == 0:
        print "INVALID padding."
        return
    m_crc = remove_padding(m_padded)
    #8
    crc = m_crc[-4:]
    m_formatted = m_crc[:-4]
    calculated_crc = struct.pack("!L", binascii.crc32(m_formatted) & 0xffffffff)
    #print calculated_crc, crc
    if calculated_crc != crc:
        print "INVALID CRC."
        return
    #9
    m_formatted_elements = m_formatted.split("\x3a")
    decrypted_sender_userid = m_formatted_elements[0]
    m = m_formatted_elements[1]
    if decrypted_sender_userid != sender_userid:
        print "sender_userid does not match."
        return
    return m


# In[162]:

def lookup_users():
    r = requests.get(server_address + "lookupUsers", headers={"Accept" : "application/json"})
    return r
def lookup_key(username):
    r = requests.get(server_address + "lookupKey/" + username, headers={"Accept" : "application/json"})
    json_obj = json.loads(r.text)
    if json_obj["status"] == "found key":
        return json_obj["keyData"]
    else:
        print "key not found."
        return None
def register_key(username, key_data):
    data = {"keyData": key_data}
    r = requests.post(server_address + "registerKey/" + username, json=data, headers={"Accept" : "application/json"})
    return r
def get_messages(username, sk_rsa_recipient, message_id, sk_dsa):
    r = requests.get(server_address + "getMessages/" + username, headers={"Accept" : "application/json"})
    json_r = json.loads(r.text)
    msg_qty = json_r["numMessages"]
    msg_qty_without_receipts = msg_qty
    if msg_qty == 0:
        return 0, message_id
    else:
        for i in range(0, msg_qty):
            encrypted_msg = json_r["messages"][i]["message"]
            sender_id = json_r["messages"][i]["senderID"]
            encoded_str = lookup_key(sender_id)
            pk_dsa_recipient, pk_dsa_sender = decode_pk(encoded_str)
            msg = decrypt_message(encrypted_msg, sk_rsa_recipient, pk_dsa_sender, sender_id)
            if msg == None:
                print "unable to decrypt message with keys."
            elif ">>>READMESSAGE" in msg:
                msg_qty_without_receipts = msg_qty_without_receipts - 1
            else:
                #print json_r["messages"][0]
                print "message id:", json_r["messages"][i]["messageID"]
                print "from:", sender_id
                print "time:", datetime.fromtimestamp(json_r["messages"][i]["sentTime"])
                print msg
                r = send_message(username, sender_id, message_id, ">>>READMESSAGE " + str(json_r["messages"][i]["messageID"]), sk_dsa)
                message_id = message_id + 1
        return msg_qty_without_receipts, message_id
def send_message(username, recipient_username, message_id, message, sk_dsa_sender):
    encoded_str = lookup_key(recipient_username)
    r_pk_rsa, r_pk_dsa = decode_pk(encoded_str)
    encrypted_message = encrypt_message(message, r_pk_rsa, sk_dsa_sender, username)
    data = {"recipient": recipient_username, "messageID": message_id, "message": encrypted_message}
    r = requests.post(server_address + "sendMessage/" + username, json=data, headers={"Accept" : "application/json"})
    return r, message_id + 1
def print_json(text_json):
    text = json.loads(text_json)
    for key in text:
        if isinstance(text[key], list) and not isinstance(text[key], basestring):
            print key + ":"
            for x in text[key]:
                print x
        else:
            print key + ":", text[key]


# In[175]:

initial_input = raw_input("please enter the server address:")
server_address = initial_input
#server_address = "http://jmessage.server.isi.jhu.edu/"
csprng = random.SystemRandom()
message_id = csprng.randint(0, 16777216)
pk_rsa, sk_rsa = None, None
pk_dsa, sk_dsa = None, None
username = None
username_input = raw_input("Please enter a username:")
username = username_input
pk_rsa, sk_rsa = rsa_keypair_gen()
pk_dsa, sk_dsa = dsa_keypair_gen()
encoded_str = encode_pk(pk_rsa, pk_dsa)
r = register_key(username, encoded_str)
if r.text == '{"result": true}':
    print "keys registered successfully."
while True:
    print "available commands:"
    print "l                      - list all usernames in the server"
    print "f <username>           - return the key fingerprint of <username>"
    print "g                      - get new messages"
    print "s <username>           - initiate sending a new message to <username>"
    print "G                      - generate a new pair of keys and register them"
    print "e                      - exit"
    user_input = raw_input("Please enter your command:")
    if user_input == "l":
        r = lookup_users()
        print_json(r.text)
    if user_input[0] == "f":
        f_user = user_input[2:]
        r = lookup_key(f_user)
        encoded_str = r.encode("utf-8")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(encoded_str)
        fp = digest.finalize().encode("hex")
        print fp
    if user_input[0] == "g":
        r, message_id = get_messages(username, sk_rsa, message_id, sk_dsa)
        if r == 0:
            print "no new messages."
    if user_input[0] == "s":
        paras = user_input.split(" ")
        recipient_user = paras[1]
        user_input_msg = raw_input("enter message to send:")
        r, message_id = send_message(username, recipient_user, message_id, user_input_msg, sk_dsa)
    if user_input[0] == "G":
        pk_rsa, sk_rsa = rsa_keypair_gen()
        pk_dsa, sk_dsa = dsa_keypair_gen()
        encoded_str = encode_pk(pk_rsa, pk_dsa)
        r = register_key(username, encoded_str)
        if r.text == '{"result": true}':
            print "keys registered successfully."
    if user_input[0] == "e":
        print "exiting jmessage client."
        break


# In[ ]:



