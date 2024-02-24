# Function to rotate right the input x by n bits
def ROR(x, n, bits=32):
    """rotate right input x, by n bits"""
    # Create a mask with n bits set to  1
    mask = (1 << n) - 1
    # Extract the bits that will be rotated
    mask_bits = x & mask
    # Perform the right rotation
    return (x >> n) | (mask_bits << (bits - n))

# Function to rotate left the input x by n bits
def ROL(x, n, bits=32):
    """rotate left input x, by n bits"""
    # Rotate left by n bits is equivalent to rotating right by (bits - n)
    return ROR(x, bits - n, bits)

# Function to convert a sentence into blocks of binary, each block being  32 bits long
def blockConverter(sentence):
    """convert input sentence into blocks of binary
       creates 4 blocks of binary each of 32 bits."""
    encoded = [] # Initialize an empty list to store the blocks
    res = "" # Initialize an empty string to build the binary representation
    # Iterate over each character in the sentence
    for i in range(0, len(sentence)):
        # When  4 characters have been processed, add the block to the list and reset the string
        if i % 4 == 0 and i != 0:
            encoded.append(res)
            res = ""
        # Convert the character to its binary representation, ensuring it's  8 bits long
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) < 8:
            temp = "0" * (8 - len(temp)) + temp
        # Append the binary representation to the current block
        res = res + temp
    # Add the last block to the list
    encoded.append(res)
    return encoded

# Function to convert an array of long integers into a string
def deBlocker(blocks):
    """converts 4 blocks array of long int into string"""
    s = "" # Initialize an empty string to build the decoded sentence
    # Iterate over each block
    for ele in blocks:
        temp = bin(ele)[2:]
        # Ensure the binary representation is  32 bits long
        if len(temp) < 32:
            temp = "0" * (32 - len(temp)) + temp
        # Convert each  8-bit chunk to its corresponding character and append to the string
        for i in range(0, 4):
            s = s + chr(int(temp[i * 8:(i + 1) * 8], 2))
    return s



# Function to encrypt a sentence using a secret key
def encrypt(sentence, secret):
    # Convert the sentence to binary blocks
    encoded = blockConverter(sentence)
    # Initialize the variables for the encryption process
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    orgi = [A, B, C, D] # Original values before encryption
    r = 12 # Number of rounds for the encryption process
    and_modulo = 0xffffffff  # 2 ** 32 - 1, used for modulo operation
    lgw = 5 # Logarithm of the word size
    B = (B + secret) & and_modulo
    D = (D + secret) & and_modulo
    # Perform the encryption rounds
    for i in range(1, r + 1):
        # Calculate the temporary values for t and u
        t_temp = (B * (2 * B + 1)) & and_modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t & 31
        umod = u & 31
        # Perform the encryption operations
        A = (ROL(A ^ t, umod, 32) + secret) & and_modulo
        C = (ROL(C ^ u, tmod, 32) + secret) & and_modulo
        # Update the variables for the next round
        (A, B, C, D) = (B, C, D, A)
    # Final updates after all rounds
    A = (A + secret) & and_modulo
    C = (C + secret) & and_modulo
    cipher = [A, B, C, D] # Encrypted values
    return orgi, cipher

# Function to decrypt a sentence using a secret key
def decrypt(esentence, secret):
    # Convert the encrypted sentence to binary blocks
    encoded = blockConverter(esentence)
    # Initialize the variables for the decryption process
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    cipher = [A, B, C, D] # Encrypted values
    r = 12 # Number of rounds for the decryption process
    and_modulo = 0xffffffff  # 2 ** 32 - 1, used for modulo operatio
    lgw = 5 # Logarithm of the word size
    C = (C - secret) & and_modulo
    A = (A - secret) & and_modulo
    # Perform the decryption rounds
    for j in range(1, r + 1):
        (A, B, C, D) = (D, A, B, C) # Update the variables for the next round
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) & and_modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t & 31
        umod = u & 31
        # Perform the decryption operations
        C = (ROR((C - secret) & and_modulo, tmod, 32) ^ u)
        A = (ROR((A - secret) & and_modulo, umod, 32) ^ t)
    # Final updates after all rounds
    D = (D - secret) & and_modulo
    B = (B - secret) & and_modulo
    orgi = [A, B, C, D] # Original values after decryption
    return cipher, orgi

# Function to decrypt multiple blocks using a single key
def decrypt_many_single_key(encrypted_blocks, key):
    decrypted_text = '' # Initialize an empty string to build the decrypted text
    # Decrypt each block and append the result to the decrypted text
    for block in encrypted_blocks:
        cipher, orgi = decrypt(block, key)
        decrypted_text += deBlocker(orgi)
    return decrypted_text

# Function to encrypt multiple sentences using a single key
def encrypt_many_single_key(lst_of_sentences, key):
    encrypted_blocks = [] # Initialize an empty list to store the encrypted blocks
    e_whole_sentence = '' # Initialize an empty string to build the encrypted sentence
    # Encrypt each sentence and append the result to the encrypted blocks
    for sent in lst_of_sentences:
        orgi, cipher = encrypt(sent, key)
        esentence = deBlocker(cipher)
        e_whole_sentence += esentence
        encrypted_blocks.append(esentence)
    return e_whole_sentence, encrypted_blocks