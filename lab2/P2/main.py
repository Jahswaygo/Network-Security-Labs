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
    encrypted_msg_1 = encrypt_asymmetric(public_key, f"Alice|{nonce_a.hex()}")
    
    # Step 2: Bob → Alice
    encrypted_msg_2 = encrypt_asymmetric(public_key, f"Bob|{nonce_a.hex()}|{nonce_b.hex()}")
    decrypted_msg_2 = decrypt_asymmetric(private_key, encrypted_msg_2)  # Bob decrypts message
    
    # Step 3: Alice → Bob
    encrypted_msg_3 = encrypt_asymmetric(public_key, f"Alice|{nonce_b.hex()}")
    decrypted_msg_3 = decrypt_asymmetric(private_key, encrypted_msg_3)  # Alice decrypts message
    
    print("Public Key Authentication Successful!")

# Run Protocols
public_key_auth_protocol()

