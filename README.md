# COE817 Network Security Labs

This repository contains hands-on implementations of various network security concepts as part of the COE817 Network Security course. Each lab progressively builds upon fundamental cryptographic principles and secure communication protocols, demonstrating both the implementation and potential vulnerabilities of different security mechanisms.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
- [Lab 1: Vigenère Cipher Implementation](#lab-1-vigenère-cipher-implementation)
- [Lab 2: Authentication Protocols](#lab-2-authentication-protocols)
- [Lab 3: Key Distribution Protocol](#lab-3-key-distribution-protocol)
- [Lab 4: Secure Group Communication](#lab-4-secure-group-communication)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [References](#references)

---

## Prerequisites

### Required Knowledge
- Basic understanding of cryptography concepts (encryption, decryption, symmetric/asymmetric keys)
- Familiarity with Python programming
- Understanding of network programming (sockets, TCP/IP)
- Knowledge of authentication protocols and key distribution

### System Requirements
- Python 3.7 or higher
- pip (Python package installer)

### Required Python Libraries
```bash
pip install cryptography rsa
```

**Core Dependencies:**
- `cryptography` - For AES encryption, RSA operations, and digital signatures
- `rsa` - For RSA key generation and encryption in some labs
- Built-in libraries: `socket`, `threading`, `os`, `json`, `time`, `signal`

---

## Installation and Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Jahswaygo/Network-Security-Labs.git
   cd Network-Security-Labs
   ```

2. **Install Dependencies:**
   ```bash
   pip install cryptography rsa
   ```

3. **Verify Installation:**
   ```bash
   python3 --version
   python3 -c "import cryptography, rsa; print('Dependencies installed successfully')"
   ```

---

## Lab 1: Vigenère Cipher Implementation

### Overview
This lab demonstrates the classical Vigenère cipher for encrypting and decrypting messages. It implements a client-server architecture where the client sends encrypted questions to the server, and the server responds with encrypted answers. The lab showcases both single-threaded and multi-threaded server implementations.

### Learning Objectives
- Understand symmetric encryption using the Vigenère cipher
- Implement client-server communication over TCP sockets
- Learn socket programming with Python
- Explore multi-threaded server architecture for concurrent connections
- Understand the limitations of classical ciphers

### Directory Structure
```
Lab1/                # Contains single-threaded implementation
└── lab1P1/
    ├── cipher.py    # Vigenère cipher encryption/decryption
    ├── client.py    # Client application
    └── server.py    # Single-threaded server

lab1/                # Contains multi-threaded implementation
└── lab1P2/
    ├── cipher.py    # Vigenère cipher encryption/decryption
    └── server.py    # Multi-threaded server
```

### Components

#### Part 1: Single-Threaded Server (lab1P1)
- **`cipher.py`**: Implements Vigenère cipher encryption and decryption functions
  - `vigenere_encrypt(plaintext, key)`: Encrypts text using the given key
  - `vigenere_decrypt(ciphertext, key)`: Decrypts text using the given key
  
- **`client.py`**: Client program that:
  - Connects to the server on localhost:65432
  - Prompts user for questions
  - Encrypts questions using key "TMU"
  - Sends encrypted questions to server
  - Receives and decrypts server responses
  
- **`server.py`**: Single-threaded server that:
  - Listens on port 65432
  - Accepts one client connection at a time
  - Decrypts incoming questions
  - Provides predefined answers to specific questions
  - Encrypts and sends responses back to client

#### Part 2: Multi-Threaded Server (lab1P2)
- **`server.py`**: Enhanced server with threading support
  - Handles multiple concurrent client connections
  - Each client handled in a separate thread
  - Same encryption/decryption logic as Part 1

### How to Run

#### Running Part 1 (Single-Threaded)

1. **Start the Server:**
   ```bash
   cd Lab1/lab1P1
   python3 server.py
   ```
   Expected output:
   ```
   Server listening on port 65432
   ```

2. **Start the Client (in a new terminal):**
   ```bash
   cd Lab1/lab1P1
   python3 client.py
   ```

3. **Interact with the System:**
   - The client will prompt: `You: `
   - Try these questions:
     - "Who created you"
     - "What does Siri mean"
     - "Are you a robot"
   
   **Example Session:**
   ```
   You: Who created you
   Siri: I was created by Apple.
   ```

4. **Stop the Server:** Press `Ctrl+C` to gracefully shutdown

#### Running Part 2 (Multi-Threaded)

1. **Start the Server:**
   ```bash
   cd lab1/lab1P2
   python3 server.py
   ```

2. **Start Multiple Clients:**
   Open multiple terminals and run:
   ```bash
   cd Lab1/lab1P1  # Use Part 1's client
   python3 client.py
   ```
   
   The server can now handle multiple clients simultaneously!

### Key Features
- **Symmetric Encryption**: Uses the same key (TMU) for encryption and decryption
- **TCP Socket Communication**: Reliable connection-oriented communication
- **Multi-threading**: Concurrent handling of multiple clients
- **Graceful Shutdown**: Server responds to SIGINT (Ctrl+C) signals

### Security Considerations
⚠️ **Important**: The Vigenère cipher is a classical cipher that is **not secure** for modern use:
- Vulnerable to frequency analysis attacks
- Can be broken with known-plaintext attacks
- Should only be used for educational purposes
- Modern applications should use AES or other approved algorithms

---

## Lab 2: Authentication Protocols

### Overview
This lab explores three progressively sophisticated authentication protocols, demonstrating the evolution from basic symmetric key authentication to advanced public key cryptography with digital signatures. Each part builds upon the previous one, addressing security vulnerabilities and adding layers of protection.

### Learning Objectives
- Understand different authentication mechanisms (symmetric vs. asymmetric)
- Learn the role of nonces in preventing replay attacks
- Implement RSA and AES encryption in Python
- Understand digital signatures and their role in message authentication
- Recognize common authentication protocol vulnerabilities

### Directory Structure
```
lab2/
├── P1/
│   └── main.py    # Symmetric key authentication (AES)
├── P2/
│   └── main.py    # Public key authentication (RSA)
└── P3/
    └── main.py    # Digital signatures with timestamps
```

### Part 1: Symmetric Key Authentication (AES)

**Protocol Overview:**
Alice and Bob share a symmetric AES key and use it to authenticate each other through nonce exchanges.

**Protocol Steps:**
1. Alice → Bob: Encrypts `{Alice, NonceA}` with shared AES key
2. Bob → Alice: Encrypts `{Bob, NonceB, NonceA}` with shared AES key  
3. Alice → Bob: Encrypts `{Alice, NonceB}` with shared AES key

**Implementation Details:**
- Uses AES-CBC mode with random IV (Initialization Vector)
- 128-bit AES key (16 bytes)
- Manual PKCS7-style padding for block alignment
- Nonces are 8-byte random values

**How to Run:**
```bash
cd lab2/P1
python3 main.py
```

**Expected Output:**
```
the sent message 1: [encrypted bytes]
the decrypted message 1: Alice to Bob | [nonce_a_hex]
the sent message 2: [encrypted bytes]
...
```

**Security Considerations:**
- ✓ Provides confidentiality through encryption
- ✓ Nonces prevent simple replay attacks
- ⚠️ Requires secure pre-shared key distribution
- ⚠️ No message integrity verification (vulnerable to tampering)

### Part 2: Public Key Authentication (RSA)

**Protocol Overview:**
Alice and Bob use RSA public key cryptography to authenticate without pre-shared secrets.

**Protocol Steps:**
1. Alice → Bob: Encrypts `{Alice, NonceA}` with Bob's public key
2. Bob → Alice: Encrypts `{Bob, NonceB, NonceA}` with Alice's public key
3. Alice → Bob: Encrypts `{Alice, NonceB}` with Bob's public key

**Implementation Details:**
- RSA key pairs generated for both Alice and Bob
- Messages encrypted with recipient's public key
- Decrypted with recipient's private key
- Each party can verify the other possesses the correct private key

**How to Run:**
```bash
cd lab2/P2
python3 main.py
```

**Expected Output:**
```
the sent message 1: [encrypted bytes]
the decrypted message 1: Alice to Bob | [nonce_a_hex]
the sent message 2: [encrypted bytes]
...
Authentication successful!
```

**Advantages over Part 1:**
- No pre-shared secret required
- Public keys can be distributed openly
- Private keys never leave their owners

**Security Considerations:**
- ✓ Solves key distribution problem
- ✓ Each party proves possession of private key
- ⚠️ No protection against man-in-the-middle attacks
- ⚠️ No message integrity verification

### Part 3: Digital Signatures with Timestamps

**Protocol Overview:**
Extends Part 2 by adding digital signatures and timestamps to provide message authentication, integrity, and replay attack protection.

**Protocol Enhancement:**
- Each message is signed with sender's private key
- Recipient verifies signature using sender's public key
- Timestamps prevent replay attacks
- Combines encryption (confidentiality) with signatures (authentication)

**Implementation Details:**
- RSA signatures using SHA-256 hash
- Timestamps included in signed data
- Messages both encrypted AND signed
- Two-layer security: encryption + authentication

**How to Run:**
```bash
cd lab2/P3
python3 main.py
```

**Expected Output:**
```
Message 1 sent and verified with signature
Message 2 sent and verified with signature
Message 3 sent and verified with signature
Authentication protocol completed successfully!
```

**Security Improvements:**
- ✓ Message authentication (confirms sender identity)
- ✓ Message integrity (detects tampering)
- ✓ Non-repudiation (sender cannot deny sending)
- ✓ Replay attack protection (timestamps)
- ✓ Confidentiality (encryption)

### Key Concepts Demonstrated
- **Nonces**: Random numbers used once to prevent replay attacks
- **Symmetric Encryption (AES)**: Fast, efficient, requires shared secret
- **Asymmetric Encryption (RSA)**: Slower, solves key distribution, enables digital signatures
- **Digital Signatures**: Prove authenticity and integrity of messages
- **Timestamps**: Provide temporal context and prevent replay attacks

### Dependencies for Lab 2
```bash
pip install cryptography
```

The `cryptography` library provides:
- `Cipher`, `algorithms`, `modes` for AES encryption
- `rsa`, `padding` for RSA operations
- `hashes` for SHA-256 in signatures

---

## Lab 3: Key Distribution Protocol

### Overview
This lab implements a Key Distribution Center (KDC) protocol to facilitate secure communication between multiple clients. The KDC acts as a trusted third party that generates and distributes both master keys and session keys, enabling clients to communicate securely without directly exchanging keys.

### Learning Objectives
- Understand the role of a Key Distribution Center in secure systems
- Learn the difference between master keys and session keys
- Implement a complete key distribution protocol
- Recognize vulnerabilities in KDC-based systems
- Understand the importance of digital signatures in preventing attacks

### Directory Structure
```
lab3/
└── main.py    # Complete KDC implementation with client simulation
```

### Protocol Architecture

**Components:**
1. **Key Distribution Center (KDC)**: Trusted third party that manages keys
2. **Clients (A, B, C)**: Multiple parties wanting to communicate securely
3. **Master Keys**: Long-term keys shared between each client and KDC
4. **Session Keys**: Temporary keys for secure communication between clients

### Protocol Flow

**Phase 1: Client Registration**
- Each client generates an RSA key pair
- Clients register their public keys with the KDC
- KDC stores client information securely

**Phase 2: Authentication**
1. Client → KDC: Encrypted `{NonceClient, KDC_ID}`
2. KDC verifies the message and client identity
3. This establishes that both parties can communicate

**Phase 3: Master Key Distribution**
1. KDC generates a unique master key for each client
2. Master key is encrypted with client's public key
3. Client decrypts master key with their private key
4. Master key is stored for future use

**Phase 4: Session Key Distribution**
1. KDC generates a session key for group communication
2. Session key + list of other participants encrypted with each client's master key
3. Format: `{SessionKey, ClientB, ClientC}` encrypted with AES using master key
4. Clients decrypt to obtain the shared session key

**Phase 5: Secure Communication**
- Clients use the session key to encrypt messages
- All group members can decrypt messages with the shared session key

### Implementation Details

**Key Features:**
- RSA encryption for master key distribution (2048-bit keys)
- AES encryption for session key distribution and message exchange (256-bit keys)
- Nonce-based authentication to prevent replay attacks
- Support for multiple clients in a group
- Centralized key management through KDC

**Cryptographic Operations:**
```python
# RSA for asymmetric operations
generate_rsa_keys() -> (public_key, private_key)
encrypt_rsa(public_key, message)
decrypt_rsa(private_key, ciphertext)

# AES for symmetric operations
generate_aes_key() -> 32-byte key
encrypt_aes(key, message) -> IV + ciphertext
decrypt_aes(key, ciphertext) -> plaintext
```

### How to Run

```bash
cd lab3
python3 main.py
```

**Expected Output:**
```
A received: [nonce_a] | KDC
B received: [nonce_b] | KDC
C received: [nonce_c] | KDC
A received KS: [session_key_hex] | B | C
B received KS: [session_key_hex] | A | C
C received KS: [session_key_hex] | A | B
```

**Interpretation:**
- First section: Each client authenticates with KDC
- Second section: Each client receives the session key and knows who else is in the group
- Clients can now use the session key to communicate securely

### Security Analysis

**Strengths:**
- ✓ Centralized key management (easier administration)
- ✓ Clients don't need to store keys for every other client
- ✓ Session keys can be updated frequently
- ✓ Master keys are distributed securely using public key crypto

**Vulnerabilities:**
- ⚠️ **Single Point of Failure**: KDC compromise affects entire system
- ⚠️ **Trust Dependency**: All clients must trust the KDC
- ⚠️ **Replay Attacks**: Without proper timestamps, old messages could be replayed
- ⚠️ **Message Authentication**: No signatures to verify message origin

**Suggested Improvements:**
1. Add digital signatures to all messages
2. Include timestamps with nonces for stronger replay protection
3. Implement certificate-based KDC authentication
4. Add key expiration and renewal mechanisms
5. Log all key distribution events for audit trails

### Key Concepts

**Master Key vs Session Key:**
- **Master Key**: Long-term key between client and KDC, used to protect session key distribution
- **Session Key**: Short-term key for actual communication, can be changed frequently

**Why Use Both?**
- Master keys are used infrequently (only for key distribution)
- Session keys are used frequently (for all messages)
- If session key is compromised, only current session is affected
- Compromise of master key requires re-registration

### Dependencies for Lab 3
```bash
pip install cryptography rsa
```

Required modules:
- `rsa` for RSA key generation and operations
- `cryptography` for AES encryption and padding
- `os` for random number generation (nonces, keys)

---

## Lab 4: Secure Group Communication

### Overview
This lab implements a comprehensive secure group communication system with a Key Distribution Center (KDC) managing multiple clients. It extends Lab 3 by adding digital signatures, message forwarding, and logging capabilities. The system enables multiple clients to securely exchange messages in a group setting with strong authentication and integrity guarantees.

### Learning Objectives
- Implement a complete secure group messaging system
- Understand digital signatures for message authentication
- Learn message forwarding through a trusted intermediary
- Implement comprehensive security logging
- Combine multiple cryptographic techniques in a real-world scenario

### Directory Structure
```
lab4/
├── crypto_utils.py    # Cryptographic utility functions
├── client.py          # Client class implementation
├── kdc.py             # Key Distribution Center implementation
└── main.py            # Main program simulating group communication
```

### System Architecture

**Components:**

1. **crypto_utils.py** - Core cryptographic functions:
   - RSA key generation and encryption/decryption
   - AES encryption/decryption with proper padding
   - Digital signature generation and verification
   - Nonce generation for authentication
   - Timestamp handling for replay protection

2. **client.py** - Client class with capabilities:
   - RSA key pair management
   - Message encryption (RSA and AES)
   - Message decryption
   - Digital signature creation
   - Signature verification
   - Nonce generation

3. **kdc.py** - Key Distribution Center with:
   - Client registration and management
   - Master key generation and distribution
   - Session key (group key) generation
   - Secure message forwarding
   - Comprehensive message logging
   - Digital signature verification

4. **main.py** - Orchestrates the complete protocol:
   - Initializes KDC and clients
   - Handles registration phase
   - Manages key distribution
   - Simulates message exchange between clients

### Complete Protocol Flow

#### Phase 1: System Initialization
```python
kdc = KDC()
clients = {client_id: Client(client_id) for client_id in ["A", "B", "C"]}
```
- KDC generates its RSA key pair and group key
- Each client generates their RSA key pair and nonce

#### Phase 2: Client Registration
```python
for client_id, client in clients.items():
    kdc.register_client(client_id, client.public_key)
```
- Clients register their public keys with KDC
- KDC maintains a registry of all participants

#### Phase 3: Initial Authentication
```python
encrypted_msg = client.encrypt_message(kdc.public_key, f"{client.nonce} | {kdc.id}")
decrypted_msg = kdc.decrypt_message(encrypted_msg)
```
- Each client encrypts their nonce + KDC ID with KDC's public key
- KDC decrypts and verifies the authentication message
- Establishes initial trust between client and KDC

#### Phase 4: Master Key Distribution
```python
master_keys = {client_id: kdc.generate_master_key() for client_id in clients}
encrypted_master_keys = {
    client_id: client.encrypt_message(client.public_key, master_keys[client_id].hex()) 
    for client_id, client in clients.items()
}
```
- KDC generates unique master key for each client
- Master key encrypted with client's public key (only client can decrypt)
- Clients decrypt and store their master keys

#### Phase 5: Session Key Distribution
```python
session_key = kdc.generate_session_key()
encrypted_session_keys = {
    client_id: client.encrypt_aes_message(
        master_key, 
        f"{session_key.hex()} | {' | '.join([other_clients])}"
    )
    for client_id, client in clients.items()
}
```
- KDC generates a shared session/group key
- Session key + participant list encrypted with each client's master key
- All clients receive the same session key
- Each client knows all other participants

#### Phase 6: Secure Group Communication
```python
# Client A sends a message
sender_id = "A"
message = "Hello from A"
timestamp = str(time.time())
encrypted_message = sender.encrypt_aes_message(
    kdc.group_key, 
    f"{sender_id} | {message} | {timestamp}"
)
signature = sender.sign_message(f"{sender_id} | {message} | {timestamp}")
kdc.forward_message(sender_id, encrypted_message, signature)
```
- Sender encrypts message with group key (confidentiality)
- Sender signs message with their private key (authentication)
- KDC receives encrypted message + signature
- KDC verifies signature using sender's public key
- KDC forwards verified message to all other clients
- Recipients decrypt with group key and verify signature

### Key Security Features

**1. Multi-Layer Encryption:**
- RSA for master key distribution (asymmetric)
- AES for session keys and messages (symmetric)
- Combines security benefits of both approaches

**2. Digital Signatures:**
- Every message is signed by sender
- Signatures provide:
  - **Authentication**: Proves sender identity
  - **Integrity**: Detects message tampering
  - **Non-repudiation**: Sender cannot deny sending

**3. Timestamp Protection:**
- Messages include timestamps
- Prevents replay attacks
- Provides temporal ordering of messages

**4. Comprehensive Logging:**
- KDC logs all message forwarding events
- Includes: sender, timestamp, signature verification status
- Enables security auditing and incident investigation

**5. Centralized Trust Model:**
- KDC acts as trusted intermediary
- Verifies all signatures before forwarding
- Prevents unauthorized messages from reaching group

### How to Run

```bash
cd lab4
python3 main.py
```

**Expected Output:**
```
A received: [nonce] | KDC
B received: [nonce] | KDC
C received: [nonce] | KDC

A received KS: [session_key] | B | C
B received KS: [session_key] | A | C
C received KS: [session_key] | A | B

KDC forwarding message from A at [timestamp]
KDC forwarding message from B at [timestamp]
```

**Output Interpretation:**
1. **Authentication Phase**: Each client successfully authenticates with KDC
2. **Key Distribution**: All clients receive the session key and participant list
3. **Message Exchange**: KDC forwards signed and encrypted messages between clients

### Security Analysis

**Strengths:**
- ✓ **Confidentiality**: All messages encrypted with AES
- ✓ **Authentication**: Digital signatures verify sender identity
- ✓ **Integrity**: Tampering detected through signature verification
- ✓ **Non-repudiation**: Cryptographic proof of message origin
- ✓ **Audit Trail**: Complete logging of all communications
- ✓ **Replay Protection**: Timestamps prevent message replay
- ✓ **Centralized Control**: KDC verifies all messages before forwarding

**Potential Vulnerabilities:**
- ⚠️ **KDC is Single Point of Failure**: Compromise affects entire system
- ⚠️ **KDC Can Read All Messages**: No end-to-end encryption
- ⚠️ **Trust Required**: Clients must trust KDC completely
- ⚠️ **Performance Bottleneck**: All traffic goes through KDC
- ⚠️ **Timestamp Synchronization**: Requires synchronized clocks

**Advanced Security Enhancements:**
1. **End-to-End Encryption**: Add per-pair encryption on top of group key
2. **Forward Secrecy**: Implement key ratcheting for future security
3. **Distributed KDC**: Use multiple KDCs with threshold cryptography
4. **Certificate Management**: Add PKI for public key authentication
5. **Rate Limiting**: Prevent DoS attacks on KDC

### Real-World Applications

This protocol models security architectures used in:
- **Corporate Messaging Systems**: Secure internal communications
- **VPN Services**: Central authentication and key distribution
- **Secure Email Gateways**: Message verification and forwarding
- **IoT Device Management**: Centralized security for device networks
- **Conference Calling**: Secure multi-party communication

### Cryptographic Functions Reference

**RSA Operations (2048-bit):**
```python
generate_rsa_keys() -> (public_key, private_key)
encrypt_rsa(public_key, message) -> ciphertext
decrypt_rsa(private_key, ciphertext) -> plaintext
```

**AES Operations (256-bit):**
```python
generate_aes_key() -> 32-byte key
encrypt_aes(key, message) -> IV (16 bytes) + ciphertext
decrypt_aes(key, ciphertext) -> plaintext
```

**Digital Signatures (RSA-SHA256):**
```python
sign_message(private_key, message) -> signature
verify_signature(public_key, message, signature) -> boolean
```

**Utility Functions:**
```python
generate_nonce() -> 16-byte random value
generate_timestamp() -> current time in seconds
```

### Dependencies for Lab 4
```bash
pip install cryptography rsa
```

**Required Modules:**
- `cryptography.hazmat.primitives.ciphers` - AES encryption
- `cryptography.hazmat.primitives.asymmetric` - RSA operations
- `cryptography.hazmat.primitives.hashes` - SHA-256 for signatures
- `cryptography.hazmat.primitives` - Padding and serialization
- `rsa` - Additional RSA functionality
- `time` - Timestamp generation

### Testing the System

**Verify Each Phase:**
1. Check client registration succeeds for all clients
2. Verify each client receives correct nonce acknowledgment
3. Confirm master keys are unique per client
4. Verify all clients receive the same session key
5. Test message encryption and signature generation
6. Verify KDC correctly forwards messages
7. Check signature verification works properly

**Security Testing:**
- Modify a message and verify signature verification fails
- Try replaying old messages (should be caught by timestamps)
- Verify KDC rejects messages with invalid signatures
- Test with wrong encryption keys to verify confidentiality

---

## Troubleshooting

### Common Issues and Solutions

**1. Import Errors - "ModuleNotFoundError: No module named 'cryptography'"**
```bash
# Solution: Install required dependencies
pip install cryptography rsa
# Or for Python 3 specifically
pip3 install cryptography rsa
```

**2. Port Already in Use (Lab 1)**
```
Error: [Errno 48] Address already in use
```
Solution:
- Check if server is already running: `lsof -i :65432`
- Kill existing process: `kill -9 <PID>`
- Or change port number in both client.py and server.py

**3. Connection Refused (Lab 1)**
```
ConnectionRefusedError: [Errno 61] Connection refused
```
Solution:
- Ensure server is started before client
- Verify server is listening on correct port
- Check firewall settings (if running on different machines)

**4. RSA Key Size Errors (Labs 2-4)**
```
ValueError: Plaintext is too long
```
Solution:
- RSA can only encrypt small amounts of data
- Use hybrid encryption (RSA for key, AES for data)
- This is already implemented in the labs

**5. Padding Errors (Labs 2-4)**
```
ValueError: Invalid padding
```
Solution:
- Ensure encryption and decryption use same key
- Verify data hasn't been corrupted in transmission
- Check IV is properly prepended/extracted

**6. Python Version Compatibility**
Some features require Python 3.7+:
```bash
# Check your Python version
python3 --version

# Upgrade if necessary (Ubuntu/Debian)
sudo apt update
sudo apt install python3.9

# macOS with Homebrew
brew install python@3.9
```

**7. Permission Errors**
```
PermissionError: [Errno 13] Permission denied
```
Solution:
- Don't use privileged ports (< 1024) without sudo
- Check file permissions: `chmod +x script.py`

### Debugging Tips

**Enable Verbose Output:**
Add print statements to see intermediate values:
```python
print(f"Encrypted message: {encrypted_message.hex()}")
print(f"Decrypted message: {decrypted_message}")
```

**Verify Cryptographic Operations:**
```python
# Test encryption/decryption round-trip
original = "test message"
encrypted = encrypt_func(key, original)
decrypted = decrypt_func(key, encrypted)
assert original == decrypted, "Encryption/Decryption failed!"
```

**Network Debugging (Lab 1):**
```bash
# Monitor network traffic
tcpdump -i lo port 65432

# Test connectivity
telnet localhost 65432
```

---

## Security Considerations

### General Security Best Practices

**1. Key Management:**
- ⚠️ Never hardcode keys in production code
- ⚠️ Keys should be generated randomly, not based on passwords
- ⚠️ Store private keys securely (encrypted at rest)
- ⚠️ Use different keys for different purposes
- ⚠️ Implement key rotation policies

**2. Encryption Standards:**
- ✓ AES is secure for symmetric encryption (use 256-bit keys)
- ✓ RSA with 2048+ bit keys is secure for asymmetric operations
- ⚠️ Vigenère cipher is **NOT secure** - for educational use only
- ✓ Always use authenticated encryption (AES-GCM) in production

**3. Authentication:**
- ✓ Always verify signatures before trusting messages
- ✓ Use nonces to prevent replay attacks
- ✓ Include timestamps for temporal ordering
- ✓ Implement rate limiting to prevent brute force

**4. Random Number Generation:**
- ✓ Use cryptographically secure random generators (`os.urandom()`)
- ⚠️ Never use `random.random()` for security purposes
- ✓ Ensure sufficient entropy in random values

**5. Protocol Design:**
- ✓ Assume the attacker can see all network traffic
- ✓ Design protocols to be resilient against active attacks
- ✓ Include version numbers in protocols for future upgrades
- ✓ Log security events for audit and incident response

### Lab-Specific Security Notes

**Lab 1 (Vigenère):**
- Historical cipher, cryptanalytically broken
- Vulnerable to frequency analysis
- Should never be used for real security

**Lab 2 (Authentication):**
- Part 1 vulnerable without MAC (message authentication code)
- Part 2 vulnerable to man-in-the-middle without PKI
- Part 3 addresses most concerns with signatures

**Lab 3 (KDC):**
- KDC is trusted party - compromise is catastrophic
- No forward secrecy - past communications compromised if keys leak
- Should add certificate-based KDC authentication

**Lab 4 (Group Communication):**
- KDC can read all messages (no end-to-end encryption)
- Single point of failure and bottleneck
- Production systems should use distributed architecture

### Production Deployment Considerations

If adapting these labs for real applications:

1. **Use Standard Libraries:**
   - TLS/SSL for transport security
   - OAuth 2.0 / OpenID Connect for authentication
   - Signal Protocol for end-to-end messaging

2. **Add Missing Features:**
   - Certificate validation (PKI)
   - Key escrow and recovery
   - Multi-factor authentication
   - Intrusion detection

3. **Performance Optimization:**
   - Hardware security modules (HSM)
   - Caching and session management
   - Load balancing for KDC

4. **Compliance:**
   - Follow NIST guidelines
   - Implement audit logging
   - Regular security assessments
   - Incident response procedures

---

## References

### Course Materials
- COE817 Network Security Course
- Toronto Metropolitan University (TMU)

### Cryptographic Standards
- **NIST FIPS 197**: Advanced Encryption Standard (AES)
- **NIST FIPS 186-4**: Digital Signature Standard (DSS)
- **RFC 8017**: RSA Cryptography Specifications

### Recommended Reading

**Books:**
- "Applied Cryptography" by Bruce Schneier
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "Network Security Essentials" by William Stallings

**Online Resources:**
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Cryptography I - Coursera by Dan Boneh](https://www.coursera.org/learn/crypto)
- [Python Cryptography Library Docs](https://cryptography.io/en/latest/)

**Academic Papers:**
- "New Directions in Cryptography" - Diffie & Hellman (1976)
- "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems" - RSA paper (1978)

### Related Technologies
- **TLS/SSL**: Transport Layer Security for network communications
- **PGP/GPG**: Pretty Good Privacy for email encryption
- **Signal Protocol**: Modern end-to-end encryption
- **Kerberos**: Network authentication protocol with KDC

---

## Contributing

Feel free to submit issues or pull requests to improve these labs. When contributing:
- Maintain educational clarity
- Document security considerations
- Include test cases for new features
- Follow existing code style

## License

This repository is for educational purposes as part of the COE817 course.

## Acknowledgments

- Professor and TAs of COE817 at Toronto Metropolitan University
- Python cryptography library maintainers
- Network security research community