import rsa
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Function to generate RSA key pairs
def generate_rsa_keys():
    # Generate a new RSA key pair with a key size of 2048 bits
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key

# Function to encrypt messages using RSA
def encrypt_rsa(public_key, message):
    # Encrypt the message using the provided public key
    return rsa.encrypt(message.encode(), public_key)

# Function to decrypt messages using RSA
def decrypt_rsa(private_key, ciphertext):
    # Decrypt the ciphertext using the provided private key and decode it to a string
    return rsa.decrypt(ciphertext, private_key).decode()

# Function to generate a symmetric AES key
def generate_aes_key():
    # Generate a random 256-bit (32 bytes) AES key
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

# Client Function to generate nonces
def generate_nonces():
    # Generate two random nonces (4 bytes each) and return their hexadecimal representations for authentication.
    return os.urandom(4).hex(), os.urandom(4).hex()

# Key Distribution Center (KDC) class
class KDC:
    def __init__(self):
        # Generate KDC's own RSA key pair
        self.public_key, self.private_key = generate_rsa_keys()
        # Dictionary to store client public keys, indexed by client ID
        self.clients = {}
    
    def register_client(self, client_id, public_key):
        # Registers a client by storing the client's public key in the dictionary
        self.clients[client_id] = public_key
    
    def generate_nonces(self):
        # Generate two random nonces (4 bytes each) and return their hexadecimal representations for authentication.
        return os.urandom(4).hex(), os.urandom(4).hex()
    
    def generate_master_key(self):
        # Generate a random master key (32 bytes) for AES encryption
        return generate_aes_key()
    
    def generate_session_key(self):
        # Generate a random session key (8 bytes) and return its hexadecimal representation for secure communication between A and B.
        return os.urandom(8).hex()

# Client simulation function
def client_program():
    # Phase 1:
    # Step 0:
    # Initialize the KDC
    kdc = KDC()
    # Generate RSA key pairs and Nonces for clients A and B
    a_public, a_private = generate_rsa_keys()
    b_public, b_private = generate_rsa_keys()
    na, nb = generate_nonces()
    
    # Step 1 : Register clients A and B with the KDC
    kdc.register_client("A", a_public)
    kdc.register_client("B", b_public)
    
    # Step 2:  KDC replies to registration
    # Generate nonces for clients A and B
    nk1, nk2 = kdc.generate_nonces()
    # Encrypt the nonces and KDC ID using the public keys of clients A and B
    encrypted_msg_1 = encrypt_rsa(a_public, f"{nk1} | KDC")
    encrypted_msg_2 = encrypt_rsa(b_public, f"{nk2} | KDC")
    # Decrypt the nonces and ID using the private keys of clients A and B
    decrypted_msg_1 = decrypt_rsa(a_private, encrypted_msg_1)
    decrypted_msg_2 = decrypt_rsa(b_private, encrypted_msg_2)
    
    # Step 3: Clients Reply to the KDC
    # Encrypt the nonces and client IDs using the public key of the KDC
    encrypted_msg_3 = encrypt_rsa(kdc.public_key, f"{na} | {decrypted_msg_1.split(' | ')[0]}")
    encrypted_msg_4 = encrypt_rsa(kdc.public_key, f"{nb} | {decrypted_msg_2.split(' | ')[0]}")
    # Decrypt the nonces and client IDs using the private key of the KDC
    decrypted_msg_3 = decrypt_rsa(kdc.private_key, encrypted_msg_3)
    decrypted_msg_4 = decrypt_rsa(kdc.private_key, encrypted_msg_4)
    
    # Step 4: KDC Reply to Clients
    # Encrypt the nonces using the public keys of clients A and B
    encrypted_msg_5 = encrypt_rsa(a_public, f"{nk1}")
    encrypted_msg_6 = encrypt_rsa(b_public, f"{nk2}")
    # Decrypt the nonces using the private keys of clients A and B
    decrypted_msg_5 = decrypt_rsa(a_private, encrypted_msg_5)
    decrypted_msg_6 = decrypt_rsa(b_private, encrypted_msg_6)
    
    # Step 5: KDC sends Master Keys to Clients    
    # Generate master keys for clients A and B
    ka = kdc.generate_master_key()
    kb = kdc.generate_master_key()

    """ Nested Implementation = Broken
    # Encrypt the master keys using the private key of KDC and each message to be sent using the public key of the clients
    encrypted_msg_7 = encrypt_rsa(a_public, encrypt_rsa(kdc.private_key, f"{ka}"))
    encrypted_msg_8 = encrypt_rsa(b_public,encrypt_rsa(kdc.private_key, f"{kb}"))
    # Decrypt the master keys using the Public key of the KDC and the master keys message using the private keys of clients A and B
    decrypted_msg_7 = decrypt_rsa(kdc.public_key,decrypt_rsa(a_private, encrypted_msg_7))
    decrypted_msg_8 = decrypt_rsa(kdc.public_key,decrypt_rsa(b_private, encrypted_msg_8))
    """
    # Encrypt the master keys using the public key of the clients
    encrypted_msg_7 = rsa.encrypt(ka, a_public)
    encrypted_msg_8 = rsa.encrypt(kb, b_public)
    # Decrypt the master keys using the private keys of clients A and B
    decrypted_msg_7 = rsa.decrypt(encrypted_msg_7, a_private)
    decrypted_msg_8 = rsa.decrypt(encrypted_msg_8, b_private)
    
    # Print the public and private key pairs of A, B, and the server
    print("Client A Public Key:", a_public.save_pkcs1().hex())
    print("Client A Private Key:", a_private.save_pkcs1().hex())
    print("Client B Public Key:", b_public.save_pkcs1().hex())
    print("Client B Private Key:", b_private.save_pkcs1().hex())
    print("Server Public Key:", kdc.public_key.save_pkcs1().hex())
    print("Server Private Key:", kdc.private_key.save_pkcs1().hex())
    # Print the decrypted KA and KB to verify they match the original master keys
    print(f"KA: {ka.hex()}")
    print(f"KB: {kb.hex()}")
    print(f"A received KA: {decrypted_msg_7.hex()}")
    print(f"B received KB: {decrypted_msg_8.hex()}")
    
    # Phase 2: 
    # Step 6 & 7: Clients Generate Session Key
    # Generate a session key for secure communication between clients A and B
    kab = kdc.generate_session_key()
    # Convert the decrypted master keys back to bytes
    decrypted_msg_7_bytes = bytes.fromhex(decrypted_msg_7.hex())
    decrypted_msg_8_bytes = bytes.fromhex(decrypted_msg_8.hex())
    # Encrypt the session key using the master keys of clients A and B
    encrypted_kab_a = encrypt_aes(decrypted_msg_7_bytes, f"{kab} | A")
    encrypted_kab_b = encrypt_aes(decrypted_msg_8_bytes, f"{kab} | B")
    # Decrypt the session key using the master keys of clients A and B
    decrypted_kab_a = decrypt_aes(decrypted_msg_7_bytes, encrypted_kab_a)
    decrypted_kab_b = decrypt_aes(decrypted_msg_8_bytes, encrypted_kab_b)
    
    # Print the decrypted session keys to verify they match the original session key
    print(f"A received KAB: {decrypted_kab_a}")
    print(f"B received KAB: {decrypted_kab_b}")    
    # Print the result of comparing both decrypted session keys
    print(f"Do both clients have the same session key? {decrypted_kab_a.split(' | ')[0] == decrypted_kab_b.split(' | ')[0]}")
"""
    Vulnerability of the Protocol
        The protocol is vulnerable to a man-in-the-middle attack.
        An attacker could intercept the communication between the KDC and the clients,
        replace the public keys with their own, and decrypt the session key.
    
    Solution to the Problem
        To solve this problem, we can use digital signatures to ensure the integrity
        and authenticity of the public keys and messages exchanged between the KDC and the clients.
        The KDC can sign the public keys and messages using its private key, and the clients
        can verify the signatures using the KDC's public key.
"""
if __name__ == "__main__":
    # Run the client simulation program
    client_program()
