import socket
from helper import process_client_request
import threading

SERVER_ADDRESS = "127.0.0.1"  # Server address
SERVER_PORT = 65432  # Server port
SECURITY_KEY = "TMU"  # Key used for Vigenère cipher encryption/decryption

# Hardcoded answers for predefined queries
assistant_responses = {
    "WHO BUILT YOU?": "I WAS BUILT BY INNOVATORS.",
    "WHAT IS YOUR NAME?": "MY NAME REPRESENTS SUCCESS AND BEAUTY.",
    "ARE YOU ARTIFICIAL?": "I AM A DIGITAL COMPANION."
}

def initialize_server():
    # Set up and run the server to handle multiple client connections.
    try:
        # Create and configure the server socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow the socket to be reused
        server.bind((SERVER_ADDRESS, SERVER_PORT))  # Bind the socket to the address and port
        server.listen()  # Listen for incoming connections
        print(f"Assistant server running at {SERVER_ADDRESS}:{SERVER_PORT}...")

        # Continuously accept client connections
        while True:
            client_socket, client_address = server.accept()  # Accept a new client connection
            client_thread = threading.Thread(
                target=process_client_request,
                args=(client_socket, client_address, assistant_responses, SECURITY_KEY),
            )  # Create a new thread to handle the client request
            client_thread.start()  # Start the thread

    except Exception as e:
        print(f"Server encountered an error: {e}")

    finally:
        server.close()  # Close the server socket
        print("Server has been shut down.")

if __name__ == "__main__":
    initialize_server()  # Start the server