# Function to rotate right the input x by n bits
from math import log2


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
    encoded = []  # Initialize an empty list to store the blocks
    res = ""  # Initialize an empty string to build the binary representation
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
    s = ""  # Initialize an empty string to build the decoded sentence
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


def _gen_rc6_key(userkey: str) -> list:
    r = 12
    w = 32
    b = len(userkey)
    modulo = 2 ** 32
    s = (2 * r + 4) * [0]
    s[0] = 0xB7E15163
    for i in range(1, 2 * r + 4):
        s[i] = (s[i - 1] + 0x9E3779B9) % (2 ** w)
    encoded = blockConverter(userkey)
    enlength = len(encoded)
    l = enlength * [0]
    for i in range(1, enlength + 1):
        l[enlength - i] = int(encoded[i - 1], 2)

    v = 3 * max(enlength, 2 * r + 4)
    A = B = i = j = 0

    for index in range(0, v):
        A = s[i] = ROL((s[i] + A + B) % modulo, 3, 32)
        B = l[j] = ROL((l[j] + A + B) % modulo, (A + B) % 32, 32)
        i = (i + 1) % (2 * r + 4)
        j = (j + 1) % enlength
    return s


# Function to encrypt a sentence using a secret key

def encrypt(sentence, s):
    s = _gen_rc6_key(str(s))
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    orgi = [A, B, C, D]
    r = 12
    w = 32
    modulo = 2 ** 32
    lgw = 5
    B = (B + s[0]) % modulo
    D = (D + s[1]) % modulo
    for i in range(1, r + 1):
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        A = (ROL(A ^ t, umod, 32) + s[2 * i]) % modulo
        C = (ROL(C ^ u, tmod, 32) + s[2 * i + 1]) % modulo
        (A, B, C, D) = (B, C, D, A)
    A = (A + s[2 * r + 2]) % modulo
    C = (C + s[2 * r + 3]) % modulo
    cipher = [A, B, C, D]
    return orgi, cipher


def decrypt(esentence, s):
    s = _gen_rc6_key(str(s))
    encoded = blockConverter(esentence)
    enlength = len(encoded)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    cipher = [A, B, C, D]
    r = 12
    w = 32
    modulo = 2 ** 32
    lgw = 5
    C = (C - s[2 * r + 3]) % modulo
    A = (A - s[2 * r + 2]) % modulo
    for j in range(1, r + 1):
        i = r + 1 - j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        C = (ROR((C - s[2 * i + 1]) % modulo, tmod, 32) ^ u)
        A = (ROR((A - s[2 * i]) % modulo, umod, 32) ^ t)
    D = (D - s[1]) % modulo
    B = (B - s[0]) % modulo
    orgi = [A, B, C, D]
    return cipher, orgi


# Function to decrypt multiple blocks using a single key
def decrypt_many_single_key(encrypted_blocks, key):
    decrypted_text = ''  # Initialize an empty string to build the decrypted text
    # Decrypt each block and append the result to the decrypted text
    for block in encrypted_blocks:
        cipher, orgi = decrypt(block, key)
        decrypted_text += deBlocker(orgi)
    return decrypted_text


# Function to encrypt multiple sentences using a single key
def encrypt_many_single_key(lst_of_sentences, key):
    encrypted_blocks = []  # Initialize an empty list to store the encrypted blocks
    e_whole_sentence = ''  # Initialize an empty string to build the encrypted sentence
    # Encrypt each sentence and append the result to the encrypted blocks
    for sent in lst_of_sentences:
        orgi, cipher = encrypt(sent, key)
        esentence = deBlocker(cipher)
        e_whole_sentence += esentence
        encrypted_blocks.append(esentence)
    return e_whole_sentence, encrypted_blocks
