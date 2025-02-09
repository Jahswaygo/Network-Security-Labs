import socket
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from base64 import b64encode, b64decode

# Asymmetric Encryption (RSA)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key  # Generate RSA public-private key pair

def encrypt_asymmetric(public_key, message):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )  # Encrypt message using RSA public key

def decrypt_asymmetric(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()  # Decrypt ciphertext using RSA private key

    # Public Key Authentication
def public_key_auth_protocol():
    private_key, public_key = generate_rsa_keys()  # Generate RSA key pair
    nonce_a = os.urandom(8)
    nonce_b = os.urandom(8)
    
    # Step 1: Alice → Bob
    # Alice encrypts a message containing her identity and a nonce, then sends it to Bob
    encrypted_msg_1 = encrypt_asymmetric(public_key, f"Alice to Bob | {nonce_a.hex()}")
    print(f"the sent message 1: {encrypted_msg_1}")
    
    # Step 2: Bob → Alice
    # Bob decrypts Alice's message, verifies the nonce, and encrypts a message containing his identity, Alice's nonce, and a new nonce, then sends it to Alice
    decrypted_msg_1 = decrypt_asymmetric(private_key, encrypted_msg_1)  # Bob decrypts Alice's message
    print(f"the decrypted message 1: {decrypted_msg_1}")
    encrypted_msg_2 = encrypt_asymmetric(public_key, f"Bob to Alice | {nonce_b.hex()} | {nonce_a.hex()}")  # Bob encrypts a message containing his identity, and Alice's nonce
    print(f"the sent message 2: {encrypted_msg_2}")

    # Step 3: Alice → Bob
    # Alice decrypts Bob's message, verifies the nonces, and encrypts a message containing her identity and Bob's nonce, then sends it to Bob
    decrypted_msg_2 = decrypt_asymmetric(private_key, encrypted_msg_2)  #Alice decrypts Bob's message
    print(f"the decrypted message 2: {decrypted_msg_2}")
    
    encrypted_msg_3 = encrypt_asymmetric(public_key, f"Alice back to Bob | {nonce_a.hex()} | {nonce_b.hex()}")  # Alice encrypts a message containing her identity and Bob's nonce
    print(f"the sent message 3: {encrypted_msg_3}")
    
    decrypted_msg_3 = decrypt_asymmetric(private_key, encrypted_msg_3)  # Bob decrypts Alice's message
    print(f"the decrypted message 3: {decrypted_msg_3}")
    
    print("Public Key Authentication Successful!")

# Run Protocols
public_key_auth_protocol()

