# COE817 Network Security Labs

This repository contains the implementation of various network security concepts as part of the COE817 course. Each lab focuses on a specific aspect of cryptography and secure communication protocols. Below is a detailed explanation of each lab and its components.

---

## Lab 1: Vigenère Cipher Implementation

### Overview
This lab demonstrates the use of the Vigenère cipher for encrypting and decrypting messages. It includes a client-server architecture where the client sends encrypted questions to the server, and the server responds with encrypted answers.

### Structure
- **lab1P1**: Basic implementation of the Vigenère cipher with a single client-server interaction.
  - `cipher.py`: Contains the implementation of the Vigenère cipher encryption and decryption functions.
  - `client.py`: The client program that sends encrypted questions to the server.
  - `server.py`: The server program that decrypts the questions, processes them, and sends encrypted answers back to the client.

- **lab1P2**: Enhanced implementation with multithreading to handle multiple clients simultaneously.
  - `cipher.py`: Same as in `lab1P1`.
  - `server.py`: A multithreaded server that can handle multiple client connections concurrently.

### Key Features
- Demonstrates symmetric encryption using the Vigenère cipher.
- Explores client-server communication over TCP sockets.
- Introduces multithreading for handling concurrent connections.

---

## Lab 2: Authentication Protocols

### Overview
This lab focuses on implementing various authentication protocols using symmetric and asymmetric encryption. It includes three parts, each building on the previous one.

### Structure
- **P1**: Symmetric Key Authentication
  - `main.py`: Implements an authentication protocol using AES encryption. The protocol involves exchanging nonces between two parties (Alice and Bob) to verify their identities.

- **P2**: Public Key Authentication
  - `main.py`: Implements an authentication protocol using RSA encryption. The protocol involves exchanging encrypted messages and nonces between Alice and Bob to establish trust.

- **P3**: Digital Signatures with Timestamps
  - `main.py`: Extends the public key authentication protocol by adding digital signatures and timestamps to prevent replay attacks. This ensures message integrity and authenticity.

### Key Features
- Demonstrates the use of symmetric (AES) and asymmetric (RSA) encryption.
- Introduces the concept of nonces for authentication.
- Explores digital signatures and timestamps for enhanced security.

---

## Lab 3: Key Distribution Protocol

### Overview
This lab implements a Key Distribution Center (KDC) to facilitate secure communication between clients. The KDC generates and distributes master keys and session keys to clients.

### Structure
- `main.py`: Implements the KDC and client simulation. The protocol involves:
  - Registering clients with the KDC.
  - Exchanging nonces for authentication.
  - Generating and distributing master keys and session keys.
  - Establishing secure communication between clients using the session key.

### Key Features
- Demonstrates the role of a KDC in secure communication.
- Explores the use of master keys and session keys.
- Highlights the vulnerabilities of the protocol and suggests solutions using digital signatures.

---

## Lab 4: Secure Group Communication

### Overview
This lab extends the concepts of secure communication to a group setting. It involves a KDC and multiple clients exchanging encrypted messages within a group.

### Structure
- `crypto_utils.py`: Contains utility functions for RSA and AES encryption, digital signatures, and nonce generation.
- `client.py`: Represents a client in the group. Each client can encrypt, decrypt, and sign messages.
- `kdc.py`: Implements the KDC, which manages client registration, key distribution, and message forwarding.
- `main.py`: Simulates the group communication protocol. The protocol involves:
  - Registering clients with the KDC.
  - Distributing master keys and session keys.
  - Forwarding encrypted messages between clients.

### Key Features
- Demonstrates secure group communication using a KDC.
- Explores the use of digital signatures for message integrity.
- Implements message forwarding and logging to ensure secure communication.

