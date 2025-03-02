from crypto_utils import *

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.public_key, self.private_key = generate_rsa_keys()
        self.nonce = generate_nonce()

    def encrypt_message(self, public_key, message):
        return encrypt_rsa(public_key, message)

    def decrypt_message(self, ciphertext):
        return decrypt_rsa(self.private_key, ciphertext)

    def encrypt_aes_message(self, key, message):
        return encrypt_aes(key, message)

    def decrypt_aes_message(self, key, ciphertext):
        return decrypt_aes(key, ciphertext)

    def sign_message(self, message):
        return sign_message(self.private_key, message)

    def verify_message(self, public_key, message, signature):
        return verify_signature(public_key, message, signature)