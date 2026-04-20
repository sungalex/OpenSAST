# SR2-4: Weak cryptographic algorithm
import hashlib
import random

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

def encrypt_data(data):
    from Crypto.Cipher import DES
    key = b'12345678'
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
