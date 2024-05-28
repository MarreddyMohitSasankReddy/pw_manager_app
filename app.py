from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import os
import json

app = Flask(__name__)

# File to store passwords and hashed master passwords
PASSWORD_STORE_FILE = 'password_store.json'

# Secret key for AES encryption
SALT = b'\x12\x34\x56\x78\x90\xab\xcd\xef'  # You can use os.urandom(8) to generate a random salt
KEY_LENGTH = 32  # AES-256
ITERATIONS = 100000

def get_aes_key(master_password):
    key = PBKDF2(master_password, SALT, dkLen=KEY_LENGTH, count=ITERATIONS)
    return key

def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_password(encrypted_password, key):
    data = base64.b64decode(encrypted_password.encode('utf-8'))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password.decode('utf-8')

def load_password_store():
    if os.path.exists(PASSWORD_STORE_FILE):
        with open(PASSWORD_STORE_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_password_store(store):
    with open(PASSWORD_STORE_FILE, 'w') as file:
        json.dump(store, file)

def hash_master_password(master_password):
    hasher = SHA256.new()
    hasher.update(master_password.encode())
    return hasher.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/store_password', methods=['POST'])
def store_password():
    data = request.json
    domain = data['domain']
    password = data['password']
    master_password = data['masterPassword']
    
    key = get_aes_key(master_password)
    encrypted_password = encrypt_password(password, key)
    hashed_master_password = hash_master_password(master_password)
    
    password_store = load_password_store()
    password_store[domain] = {
        'encrypted_password': encrypted_password,
        'hashed_master_password': hashed_master_password
    }
    save_password_store(password_store)
    
    return jsonify({"message": "Password stored successfully"})

@app.route('/retrieve_password', methods=['POST'])
def retrieve_password():
    data = request.json
    domain = data['domain']
    master_password = data['masterPassword']
    
    password_store = load_password_store()
    if domain not in password_store:
        return jsonify({"error": "Domain not found"})
    
    entry = password_store[domain]
    hashed_master_password = entry['hashed_master_password']
    
    if hash_master_password(master_password) != hashed_master_password:
        return jsonify({"error": "Invalid master password"})
    
    key = get_aes_key(master_password)
    encrypted_password = entry['encrypted_password']
    
    try:
        decrypted_password = decrypt_password(encrypted_password, key)
        return jsonify({"password": decrypted_password})
    except (ValueError, KeyError):
        return jsonify({"error": "Error decrypting password"})

if __name__ == '__main__':
    app.run(debug=True)
