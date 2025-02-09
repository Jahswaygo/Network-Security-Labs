import socket
import os
import json
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from base64 import b64encode, b64decode
sys.path.append('../')
from P2.main import generate_rsa_keys

# Digital Signatures
def sign_message(private_key, message):
    return private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )  # Sign message using RSA private key

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature verified successfully
    except:
        return False  # Signature verification failed

# Digital Signature Authentication
def digital_signature_protocol():
    private_key, public_key = generate_rsa_keys()  # Generate RSA key pair
    message = "Secure message from Alice to Bob"
    signature = sign_message(private_key, message)  # Sign message
    
    if verify_signature(public_key, message, signature):
        print("Signature Verified: Authentication Successful!")
    else:
        print("Authentication Failed!")

# Run Protocols
digital_signature_protocol()
