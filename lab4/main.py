import time
from kdc import KDC
from client import Client

# Client simulation function
def client_program():
    kdc = KDC()
    clients = {client_id: Client(client_id) for client_id in ["A", "B", "C"]}

    # Register clients with the KDC
    for client_id, client in clients.items():
        kdc.register_client(client_id, client.public_key)

    # Each client sends an encrypted message to the KDC and receives a decrypted message back
    for client_id, client in clients.items():
        encrypted_msg = client.encrypt_message(kdc.public_key, f"{client.nonce} | {kdc.id}")
        decrypted_msg = kdc.decrypt_message(encrypted_msg)
        print(f"{client_id} received: {decrypted_msg}")

    # Generate master keys for each client
    master_keys = {client_id: kdc.generate_master_key() for client_id in clients}
    encrypted_master_keys = {client_id: client.encrypt_message(client.public_key, master_keys[client_id].hex()) for client_id, client in clients.items()}
    decrypted_master_keys = {client_id: client.decrypt_message(encrypted_master_keys[client_id]) for client_id, client in clients.items()}

    # Generate a session key and distribute it to all clients
    session_key = kdc.generate_session_key()
    encrypted_session_keys = {client_id: client.encrypt_aes_message(bytes.fromhex(decrypted_master_keys[client_id]), f"{session_key.hex()} | {' | '.join([cid for cid in clients if cid != client_id])}") for client_id, client in clients.items()}
    decrypted_session_keys = {client_id: client.decrypt_aes_message(bytes.fromhex(decrypted_master_keys[client_id]), encrypted_session_keys[client_id]) for client_id, client in clients.items()}

    # Print the session keys received by each client
    for client_id, decrypted_session_key in decrypted_session_keys.items():
        print(f"{client_id} received KS: {decrypted_session_key}")

    # Client A sends a message
    sender_id = "A"
    sender = clients[sender_id]
    message = "Hello from A"
    timestamp = str(time.time())
    encrypted_message = sender.encrypt_aes_message(kdc.group_key, f"{sender_id} | {message} | {timestamp}")
    signature = sender.sign_message(f"{sender_id} | {message} | {timestamp}")
    kdc.forward_message(sender_id, encrypted_message, signature)

    # Client B sends a message
    sender_id = "B"
    sender = clients[sender_id]
    message = "Hello from B"
    timestamp = str(time.time())
    encrypted_message = sender.encrypt_aes_message(kdc.group_key, f"{sender_id} | {message} | {timestamp}")
    signature = sender.sign_message(f"{sender_id} | {message} | {timestamp}")
    kdc.forward_message(sender_id, encrypted_message, signature)

    # Client C sends a message
    sender_id = "C"
    sender = clients[sender_id]
    message = "Hello from C"
    timestamp = str(time.time())
    encrypted_message = sender.encrypt_aes_message(kdc.group_key, f"{sender_id} | {message} | {timestamp}")
    signature = sender.sign_message(f"{sender_id} | {message} | {timestamp}")
    kdc.forward_message(sender_id, encrypted_message, signature)

if __name__ == "__main__":
    client_program()