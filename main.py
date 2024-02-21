import random
import sys

# import prime_helpers
from constants import *
"""
From Rotem :
Now prime and generator are both given, and keys are randomly generated in range of prime // 2 to prime (roughly).
TODO - define proper process to weed out weak keys.
"""


# rotate right input x, by n bits
def ROR(x, n, bits=32):
    mask = (1 << n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


# rotate left input x, by n bits
def ROL(x, n, bits=32):
    return ROR(x, bits - n, bits)


# convert input sentence into blocks of binary
# creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for i in range(0, len(sentence)):
        if i % 4 == 0 and i != 0:
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) < 8:
            temp = "0" * (8 - len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded


# converts 4 blocks array of long int into string
def deBlocker(blocks):
    s = ""
    for ele in blocks:
        temp = bin(ele)[2:]
        if len(temp) < 32:
            temp = "0" * (32 - len(temp)) + temp
        for i in range(0, 4):
            s = s + chr(int(temp[i * 8:(i + 1) * 8], 2))
    return s


# generate key s[0... 2r+3] from given input string userkey
'''generateKey(userkey)'''


def get_safe_key(prime):
    # not safe yet, but huge range for keys
    k=random.randint((prime-1) // 2, prime-1)
    if not k & 1:
        k -= 1
    return k


def generateKeys():
    # auto generate prime and primitive (read prime helpers, sympy is required for root as it's too hard :) )
    P, G = PRIME, GENERATOR
    print(f"Using prime: {P} with generator {G}")

    # auto generate Private Keys
    x1, x2 = get_safe_key(P), get_safe_key(P)
    # print(f"Generated private keys: {x1=}, {x2=}")

    # Calculate Public Keys:
    # the whole op stays in C and is faster
    y1, y2 = pow(G, x1, P), pow(G, x2, P)

    # Generate Secret Keys
    k1, k2 = pow(y2, x1, P), pow(y1, x2, P)
    # print(f"\nSecret Key For User 1 Is {k1}\nSecret Key For User 2 Is {k2}\n")

    # if k1 == k2:
        # print("Keys Have Been Exchanged Successfully")
    # else:
        # print("Keys Have Not Been Exchanged Successfully")

    assert k1 == k2
    return k1, k2


def encrypt(sentence, secret):
    encoded = blockConverter(sentence)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    orgi = [A, B, C, D]
    r = 12
    and_modulo = 0xffffffff  # 2 ** 32 - 1
    lgw = 5
    B = (B + secret) & and_modulo
    D = (D + secret) & and_modulo
    for i in range(1, r + 1):
        t_temp = (B * (2 * B + 1)) & and_modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t & 31
        umod = u & 31
        A = (ROL(A ^ t, umod, 32) + secret) & and_modulo
        C = (ROL(C ^ u, tmod, 32) + secret) & and_modulo
        (A, B, C, D) = (B, C, D, A)
    A = (A + secret) & and_modulo
    C = (C + secret) & and_modulo
    cipher = [A, B, C, D]
    return orgi, cipher


def decrypt(esentence, secret):
    encoded = blockConverter(esentence)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    cipher = [A, B, C, D]
    r = 12
    and_modulo = 0xffffffff  # 2 ** 32 - 1
    lgw = 5
    C = (C - secret) & and_modulo
    A = (A - secret) & and_modulo
    for j in range(1, r + 1):
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) & and_modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t & 31
        umod = u & 31
        C = (ROR((C - secret) & and_modulo, tmod, 32) ^ u)
        A = (ROR((A - secret) & and_modulo, umod, 32) ^ t)
    D = (D - secret) & and_modulo
    B = (B - secret) & and_modulo
    orgi = [A, B, C, D]
    return cipher, orgi


def rotems_main():
    # an attempt to encrypt-decrypt a block of blocks
    sentence = input("Enter Sentence: ")
    # random "sentence" generator for testing
    # sentence = ''.join([chr(random.randint(ord('A'), ord('z')))
    #          for _ in range(random.randint(20, 45))])

    # split message to 128 bits blocks
    lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != 16:
            lst_of_sentences[i] = sent + ' ' * (16 - len(sent))

    print(f'Input:\t {sentence}')

    secret1, secret2 = generateKeys()

    # for debug     , for decryption / to send
    e_whole_sentence, encrypted_blocks = encrypt_many_single_key(lst_of_sentences, secret1)

    tmp = e_whole_sentence.encode()
    print(f'Encrypted String (as binary): {tmp}')

    decrypted_text = decrypt_many_single_key(encrypted_blocks, secret2)
    try:
        assert decrypted_text[:len(sentence)] == sentence
    except AssertionError:
        print(f"ERROR - encryption-decryption process failed!\nsrc: {sentence}\ndest: {decrypted_text}",
              file=sys.stderr)
        exit(-1)

    print("\nDecrypted:\t", decrypted_text)


def decrypt_many_single_key(encrypted_blocks, key):
    decrypted_text = ''
    for block in encrypted_blocks:
        cipher, orgi = decrypt(block, key)
        decrypted_text += deBlocker(orgi)
    return decrypted_text


def encrypt_many_single_key(lst_of_sentences, key):
    encrypted_blocks = []
    e_whole_sentence = ''
    for sent in lst_of_sentences:
        orgi, cipher = encrypt(sent, key)
        esentence = deBlocker(cipher)
        e_whole_sentence += esentence
        encrypted_blocks.append(esentence)
    return e_whole_sentence, encrypted_blocks


def main():
    sentence = input("Enter Sentence (0-16 characters): ")

    sentence = sentence + " " * max(0, (16 - len(sentence)))
    secret1, secret2 = generateKeys()
    sentence = sentence[:16]

    orgi, cipher = encrypt(sentence, secret1)
    esentence = deBlocker(cipher)

    print("Input:\t " + sentence)

    print("\nOriginal String list: ", orgi)
    print("Length of Input String: ", len(sentence))

    print("\nEncrypted String list: ", cipher)
    print("Encrypted String: " + esentence)
    print("Length of Encrypted String: ", len(esentence))

    cipher, orgi = decrypt(esentence, secret2)
    sentence = deBlocker(orgi)
    print("\nDecrypted:\t", sentence)


if __name__ == "__main__":
    #main()
    # now calling my main
    rotems_main()
