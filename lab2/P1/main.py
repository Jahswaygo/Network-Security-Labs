import socket
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from base64 import b64encode, b64decode

# Symmetric Encryption (AES)
def generate_symmetric_key():
    return os.urandom(16)  # Generate a random 16-byte AES key

def encrypt_symmetric(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_text = plaintext.ljust(16 * ((len(plaintext) // 16) + 1))  # Manually pad to block size
    ciphertext = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to ciphertext

def decrypt_symmetric(key, ciphertext):
    iv, ciphertext = ciphertext[:16], ciphertext[16:]  # Extract IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_text.strip().decode()  # Remove padding and decode

# Authentication Protocol (Symmetric)
def symmetric_auth_protocol():
    key = generate_symmetric_key()  # Generate a symmetric key
    nonce_a = os.urandom(8)  # Generate a random nonce for Alice
    nonce_b = os.urandom(8)  # Generate a random nonce for Bob
    
    # Step 1: Alice → Bob
    # Alice encrypts a message containing her identity and a nonce, then sends it to Bob
    encrypted_msg_1 = encrypt_symmetric(key, f"Alice to Bob | {nonce_a.hex()}")
    print(f"the sent message 1: {encrypted_msg_1}")
    
    # Step 2: Bob → Alice
    # Bob decrypts Alice's message, verifies the nonce, and encrypts a message containing his identity, Alice's nonce, and a new nonce, then sends it to Alice
    decrypted_msg_1 = decrypt_symmetric(key, encrypted_msg_1)  # Bob decrypts Alice's message
    print(f"the decrypted message 1: {decrypted_msg_1}")
    encrypted_msg_2 = encrypt_symmetric(key, f"Bob to Alice | {nonce_b.hex()} | {nonce_a.hex()}")  # Bob encrypts a message containing his identity, and Alice's nonce
    print(f"the sent message 2: {encrypted_msg_2}")

    # Step 3: Alice → Bob
    # Alice decrypts Bob's message, verifies the nonces, and encrypts a message containing her identity and Bob's nonce, then sends it to Bob
    decrypted_msg_2 = decrypt_symmetric(key, encrypted_msg_2)  #Alice decrypts Bob's message
    print(f"the decrypted message 2: {decrypted_msg_2}")
    
    encrypted_msg_3 = encrypt_symmetric(key, f"Alice back to Bob | {nonce_a.hex()} | {nonce_b.hex()}")  # Alice encrypts a message containing her identity and Bob's nonce
    print(f"the sent message 3: {encrypted_msg_3}")
    
    decrypted_msg_3 = decrypt_symmetric(key, encrypted_msg_3)  # Bob decrypts Alice's message
    print(f"the decrypted message 3: {decrypted_msg_3}")
    
    print("Authentication Successful!")

# Run Protocols
symmetric_auth_protocol()