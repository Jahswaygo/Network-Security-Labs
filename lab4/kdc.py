from crypto_utils import *

class KDC:
    def __init__(self):
        self.id = "KDC"
        self.public_key, self.private_key = generate_rsa_keys()
        self.clients = {}
        self.group_key = generate_aes_key()
        self.message_log = set()

    def register_client(self, client_id, public_key):
        self.clients[client_id] = public_key, generate_nonce()

    def get_nonce(self, client_id):
        return self.clients.get(client_id, (None, None))[1]

    def generate_master_key(self):
        return generate_aes_key()

    def generate_session_key(self):
        return generate_aes_key()

    def decrypt_message(self, ciphertext):
        return decrypt_rsa(self.private_key, ciphertext)

    def forward_message(self, sender_id, encrypted_message, signature):
        if encrypted_message not in self.message_log:
            self.message_log.add(encrypted_message)
            for client_id in self.clients.keys():
                if client_id != sender_id:
                    print(f"Forwarding message to {client_id}")
                    print(f"Encrypted message: {encrypted_message}")
                    print(f"Signature: {signature}")
                    # Simulate the client receiving and processing the message
                    self.receive_message(client_id, encrypted_message, signature)

    def receive_message(self, client_id, encrypted_message, signature):
        decrypted_message = decrypt_aes(self.group_key, encrypted_message)
        sender_id, message, timestamp = decrypted_message.split(" | ", 2)
        sender_public_key, _ = self.clients[sender_id]
        if verify_signature(sender_public_key, f"{sender_id} | {message} | {timestamp}", signature):
            if verify_timestamp(float(timestamp), 1):
                print(f"{client_id} received message from {sender_id}: {message}")
            else:
                print(f"{client_id} received a message with an invalid timestamp from {sender_id}")
        else:
            print(f"{client_id} received an invalid message from {sender_id}")