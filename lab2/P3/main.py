import socket
import os
import json
import sys
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from base64 import b64encode, b64decode
sys.path.append('../')
from P2.main import generate_rsa_keys, encrypt_asymmetric, decrypt_asymmetric

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

def verify_timestamp(received_timestamp, step_number):
    if abs(time.time() - received_timestamp) > 60:  # Allow a 60-second window
        print(f"Timestamp Verification Failed: Step {step_number}")
        return False
    print(f"Timestamp Verification Successful: Step {step_number}")
    return True

# Digital Signature Authentication with Timestamps
def digital_signature_protocol():
    private_key, public_key = generate_rsa_keys()  # Generate RSA key pair
    nonce_a = os.urandom(8)  # Generate a random nonce for Alice
    nonce_b = os.urandom(8)  # Generate a random nonce for Bob
    timestamp = int(time.time())  # Generate a timestamp
    
    # Step 1: Alice → Bob
    # Alice encrypts a message containing her identity, a nonce, and a timestamp, then sends it to Bob
    message_1 = f"Alice to Bob | {nonce_a.hex()} | {timestamp}"
    signature_1 = sign_message(private_key, message_1)  # Sign message
    encrypted_msg_1 = encrypt_asymmetric(public_key, message_1)
    print(f"the sent message 1: {encrypted_msg_1}")
    print(f"the sent signature 1: {b64encode(signature_1).decode()}")  # Show the sent signature
    
    # Step 2: Bob → Alice
    # Bob decrypts Alice's message, verifies the nonce and timestamp, and encrypts a message containing his identity, Alice's nonce, a new nonce, and a timestamp, then sends it to Alice
    decrypted_msg_1 = decrypt_asymmetric(private_key, encrypted_msg_1)  # Bob decrypts Alice's message
    print(f"the decrypted message 1: {decrypted_msg_1}")
    if verify_signature(public_key, decrypted_msg_1, signature_1):
        print("Signature Verified: Step 1 Successful!")
        # Verify timestamp to prevent replay attack
        received_timestamp = int(decrypted_msg_1.split('|')[2].strip())
        if not verify_timestamp(received_timestamp, 1):
            return
    else:
        print("Signature Verification Failed: Step 1")
        return
    
    message_2 = f"Bob to Alice | {nonce_b.hex()} | {nonce_a.hex()} | {timestamp}"
    signature_2 = sign_message(private_key, message_2)  # Sign message
    encrypted_msg_2 = encrypt_asymmetric(public_key, message_2)  # Bob encrypts a message containing his identity, and Alice's nonce
    print(f"the sent message 2: {encrypted_msg_2}")
    print(f"the sent signature 2: {b64encode(signature_2).decode()}")  # Show the sent signature

    # Step 3: Alice → Bob
    # Alice decrypts Bob's message, verifies the nonces and timestamp, and encrypts a message containing her identity and Bob's nonce, then sends it to Bob
    decrypted_msg_2 = decrypt_asymmetric(private_key, encrypted_msg_2)  # Alice decrypts Bob's message
    print(f"the decrypted message 2: {decrypted_msg_2}")
    if verify_signature(public_key, decrypted_msg_2, signature_2):
        print("Signature Verified: Step 2 Successful!")
        # Verify timestamp to prevent replay attack
        received_timestamp = int(decrypted_msg_2.split('|')[3].strip())
        if not verify_timestamp(received_timestamp, 2):
            return
    else:
        print("Signature Verification Failed: Step 2")
        return
    
    message_3 = f"Alice back to Bob | {nonce_a.hex()} | {nonce_b.hex()} | {timestamp}"
    signature_3 = sign_message(private_key, message_3)  # Sign message
    encrypted_msg_3 = encrypt_asymmetric(public_key, message_3)  # Alice encrypts a message containing her identity and Bob's nonce
    print(f"the sent message 3: {encrypted_msg_3}")
    print(f"the sent signature 3: {b64encode(signature_3).decode()}")  # Show the sent signature
    
    decrypted_msg_3 = decrypt_asymmetric(private_key, encrypted_msg_3)  # Bob decrypts Alice's message
    print(f"the decrypted message 3: {decrypted_msg_3}")
    if verify_signature(public_key, decrypted_msg_3, signature_3):
        print("Signature Verified: Step 3 Successful!")
        # Verify timestamp to prevent replay attack
        received_timestamp = int(decrypted_msg_3.split('|')[3].strip())
        if not verify_timestamp(received_timestamp, 3):
            return
    else:
        print("Signature Verification Failed: Step 3")
        return
    
    print("Public Key Authentication Successful!")

# Run Protocols
digital_signature_protocol()
