import socket
from helper import encode_text, decode_text

# Constants
ADDRESS = ("127.0.0.1", 65432)  # Server address and port
AUTH_KEY = "TMU"  # Key used for Vigenère cipher encryption/decryption

def get_user_input():
    # Prompt the user for a message to send.
    return input("Enter your query (type 'DISCONNECT' to quit): ").strip().upper()

def send_encrypted_message(connection, message, key):
    # Encrypt and send a message through the socket.
    encoded_message = encode_text(message, key)  # Encrypt the message
    connection.sendall(encoded_message.encode())  # Send the encrypted message
    return encoded_message

def receive_and_decrypt_message(connection, key):
    # Receive an encrypted message from the server and decrypt it.
    received_data = connection.recv(1024).decode()  # Receive the encrypted message
    return decode_text(received_data, key), received_data  # Decrypt the message and return both decrypted and encrypted data

def chat_with_server():
    # Main function to handle communication with the server.
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket
        connection.connect(ADDRESS)  # Connect to the server
        print("Connected to the server. Type 'DISCONNECT' to terminate the session.")

        while True:
            user_message = get_user_input()  # Get user input

            if user_message == "DISCONNECT":
                print("Disconnecting... Goodbye!")
                break

            # Encrypt and send the user's message
            encrypted_request = send_encrypted_message(connection, user_message, AUTH_KEY)
            print(f"Sent encrypted data: {encrypted_request}")

            # Receive and decrypt the server's response
            decrypted_response, encrypted_response = receive_and_decrypt_message(connection, AUTH_KEY)
            print(f"Received encrypted response: {encrypted_response}")
            print(f"Server's reply: {decrypted_response}")

    except ConnectionError as conn_err:
        print(f"Connection error: {conn_err}")

    finally:
        connection.close()  # Close the connection
        print("Connection closed.")

if __name__ == "__main__":
    chat_with_server()  # Start the client