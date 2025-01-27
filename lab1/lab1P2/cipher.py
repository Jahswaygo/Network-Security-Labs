def vigenere_encrypt(plaintext, key):
    # Convert the key to uppercase to ensure uniformity
    key = key.upper()
    encrypted = []  # List to store the encrypted characters
    key_index = 0  # Index to keep track of the position in the key

    # Iterate over each character in the plaintext
    for char in plaintext:
        if char.isalpha():  # Check if the character is an alphabet letter
            # Calculate the shift using the corresponding character in the key
            shift = ord(key[key_index]) - ord('A')
            # Encrypt the character by shifting it and wrapping around using modulo 26
            encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            encrypted.append(encrypted_char)  # Append the encrypted character to the list
            # Move to the next character in the key, wrapping around if necessary
            key_index = (key_index + 1) % len(key)
        else:
            # If the character is not an alphabet letter, append it as is
            encrypted.append(char)
    
    # Join the list of encrypted characters into a single string and return it
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    # Convert the key to uppercase to ensure uniformity
    key = key.upper()
    decrypted = []  # List to store the decrypted characters
    key_index = 0  # Index to keep track of the position in the key

    # Iterate over each character in the ciphertext
    for char in ciphertext:
        if char.isalpha():  # Check if the character is an alphabet letter
            # Calculate the shift using the corresponding character in the key
            shift = ord(key[key_index]) - ord('A')
            # Decrypt the character by shifting it back and wrapping around using modulo 26
            decrypted_char = chr((ord(char.upper()) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted.append(decrypted_char)  # Append the decrypted character to the list
            # Move to the next character in the key, wrapping around if necessary
            key_index = (key_index + 1) % len(key)
        else:
            # If the character is not an alphabet letter, append it as is
            decrypted.append(char)
    
    # Join the list of decrypted characters into a single string and return it
    return ''.join(decrypted)