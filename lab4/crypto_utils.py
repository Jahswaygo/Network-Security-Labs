import rsa
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Function to generate RSA key pairs
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key

# Function to encrypt messages using RSA
def encrypt_rsa(public_key, message):
    return rsa.encrypt(message.encode(), public_key)

# Function to decrypt messages using RSA
def decrypt_rsa(private_key, ciphertext):
    return rsa.decrypt(ciphertext, private_key).decode()

# Function to generate a symmetric AES key
def generate_aes_key():
    return os.urandom(32)

# Function to encrypt messages using AES
def encrypt_aes(key, message):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct

# Function to decrypt messages using AES
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# Function to generate nonces
def generate_nonce():
    return os.urandom(4).hex()

# Digital Signatures
def sign_message(private_key, message):
    return rsa.sign(message.encode(), private_key, 'SHA-256')

def verify_signature(public_key, message, signature):
    try:
        rsa.verify(message.encode(), signature, public_key)
        return True  # Signature verified successfully
    except rsa.VerificationError:
        return False  # Signature verification failed

def verify_timestamp(received_timestamp, step_number):
    if abs(time.time() - received_timestamp) > 60:  # Allow a 60-second window
        print(f"Timestamp Verification Failed: Step {step_number}")
        return False
    print(f"Timestamp Verification Successful: Step {step_number}")
    return True