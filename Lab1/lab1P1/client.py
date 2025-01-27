import socket
from cipher import vigenere_encrypt, vigenere_decrypt

def main():
    key = "TMU"  # Vigenère cipher key
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket
    client.connect(("127.0.0.1", 65432))  # Connect to the server at localhost on port 9999

    while True:
        # Prompt the user to enter a question
        question = input("You: ")
        
        # Encrypt the question using the Vigenère cipher
        encrypted_question = vigenere_encrypt(question, key)
        
        # Send the encrypted question to the server
        client.send(encrypted_question.encode())

        # Receive the encrypted answer from the server
        encrypted_answer = client.recv(1024).decode()
        
        # Decrypt the received answer using the Vigenère cipher
        answer = vigenere_decrypt(encrypted_answer, key)
        
        # Print the decrypted answer
        print(f"Siri: {answer}")

# Entry point of the script
if __name__ == "__main__":
    main()