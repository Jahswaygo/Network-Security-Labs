import socket
from cipher import vigenere_encrypt, vigenere_decrypt

# Function to handle communication with a connected client
def handle_client(client_socket, key):
    while True:
        # Receive the encrypted question from the client
        encrypted_question = client_socket.recv(1024).decode()
        if not encrypted_question:
            break  # Exit the loop if no data is received (client disconnected)
        
        print(f"Encrypted question: {encrypted_question}")
        
        # Decrypt the received question using the Vigenère cipher
        question = vigenere_decrypt(encrypted_question, key)
        print(f"Decrypted question: {question}")

        # Get the answer to the question
        answer = get_answer(question)
        
        # Encrypt the answer using the Vigenère cipher
        encrypted_answer = vigenere_encrypt(answer, key)
        
        # Send the encrypted answer back to the client
        client_socket.send(encrypted_answer.encode())

    # Close the client socket after communication ends
    client_socket.close()

# Function to get the answer to a given question
def get_answer(question):
    # Predefined responses to specific questions
    responses = {
        "WHO CREATED YOU": "I was created by Apple.",
        "WHAT DOES SIRI MEAN": "Victory and beautiful.",
        "ARE YOU A ROBOT": "I am a virtual assistant."
    }
    # Return the response if the question is known, otherwise return a default response
    return responses.get(question.upper(), "I don't understand the question.")

# Main function to set up the server and handle incoming connections
def main():
    key = "TMU"  # Vigenère cipher key
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket
    server.bind(("0.0.0.0", 9999))  # Bind the socket to all available interfaces on port 9999
    server.listen(1)  # Listen for incoming connections (max 1 connection in the queue)
    print("Server listening on port 9999")

    while True:
        # Accept a new client connection
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        
        # Handle the client connection in a separate function
        handle_client(client_socket, key)

# Entry point of the script
if __name__ == "__main__":
    main()