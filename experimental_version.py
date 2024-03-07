import random
import sys
# hash imports
import hashlib
from math import log2

# Schnorr import
import schnorr_lib

# import prime_helpers
from constants import *
import sympy

USE_MULTIPRIME = 0
PRIME_COUNT = 4 if USE_MULTIPRIME else 2
p1 = sympy.nextprime(2 ** 6)
primes = [p1]
for _ in range(PRIME_COUNT - 1):
    primes.append(sympy.nextprime(primes[-1] + 1))
import tqdm

# test ignore
n = 1
for i in range(PRIME_COUNT):
    n *= primes[i]
k = random.randint(primes[0] + 1, primes[-1] - 1) % n
count = sum([1 if (pow(i, k, n) == i) else 0 for i in tqdm.tqdm(range(2**20))])
print(f"Unhidden messages: {count}")
exit()
# end test end ignore

# attempt to generalize block and key sizes for RC6:
INPUT_SIZE_BITS = 2048
INPUT_SIZE_BYTES = INPUT_SIZE_BITS // 8
BLOCK_SIZE_BITS = INPUT_SIZE_BITS // 4
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS // 8
LOG_BLOCK_SIZE_BITS = int(log2(BLOCK_SIZE_BITS))


def ROR(x, n, bits=32):
    """rotate right input x, by n bits"""
    mask = (1 << n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


def ROL(x, n, bits=32):
    """rotate left input x, by n bits"""
    return ROR(x, bits - n, bits)


def blockConverter(sentence):
    """convert input sentence into blocks of binary
       creates 4 blocks of binary each of BLOCK_SIZE/4 bits."""
    encoded = []
    res = ""
    for i in range(0, len(sentence)):
        if i % (INPUT_SIZE_BYTES // 4) == 0 and i != 0:
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) < 8:
            temp = "0" * (8 - len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded


def deBlocker(blocks):
    """converts 4 blocks array of long int into string"""
    s = ""
    for ele in blocks:
        temp = bin(ele)[2:]
        # print(f"deBlocker working on element {temp}\n",file=sys.stderr)
        if len(temp) < BLOCK_SIZE_BITS:
            temp = "0" * (BLOCK_SIZE_BITS - len(temp)) + temp
        for i in range(0, BLOCK_SIZE_BYTES):
            # print(f"Appending to {s}: {s} + {chr(int(temp[i * 8:(i + 1) * 8], 2))=}")
            s = s + chr(int(temp[i * 8:(i + 1) * 8], 2))
    # print(f"Input:\n{blocks}\nOutput:\n{s}")
    return s


def get_safe_key(prime):
    """Get odd key between prime // 2 and prime - 1"""
    # not safe yet, but huge range for keys
    # for n bit prime, we get n - 1 bits of keyspace (in current version, 2047 bits)
    k = random.randint((prime - 1) // 2, (prime - 1))
    if not k & 1:
        k -= 1
    return k


def generateKeys():
    # prime and generator are given in constants.
    P, G = PRIME, GENERATOR
    # print(f"Using prime: {P} with generator {G}")

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
    # changed to 2048 bits
    and_modulo = (2 ** BLOCK_SIZE_BITS) - 1
    lgw = LOG_BLOCK_SIZE_BITS
    B = (B + secret[0]) & and_modulo
    D = (D + secret[1]) & and_modulo
    for i in range(1, r + 1):
        t_temp = (B * (2 * B + 1)) & and_modulo
        # 32 and 31 respectively changed to 512 511
        t = ROL(t_temp, lgw, BLOCK_SIZE_BITS)
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, BLOCK_SIZE_BITS)
        tmod = t & (BLOCK_SIZE_BITS - 1)
        umod = u & (BLOCK_SIZE_BITS - 1)
        A = (ROL(A ^ t, umod, BLOCK_SIZE_BITS) + secret[2 * i]) & and_modulo
        C = (ROL(C ^ u, tmod, BLOCK_SIZE_BITS) + secret[2 * i + 1]) & and_modulo
        (A, B, C, D) = (B, C, D, A)
    A = (A + secret[2 * r + 2]) & and_modulo
    C = (C + secret[2 * r + 3]) & and_modulo
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
    # and_modulo = 0xffffffff  # 2 ** 32 - 1
    and_modulo = (2 ** BLOCK_SIZE_BITS) - 1
    # forgot to modify lgw, it needs to be log2(blocksize) = log2(512)=9
    lgw = LOG_BLOCK_SIZE_BITS
    C = (C - secret[2 * r + 3]) & and_modulo
    A = (A - secret[2 * r + 2]) & and_modulo
    for j in range(1, r + 1):
        i = r + 1 - j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) & and_modulo
        u = ROL(u_temp, lgw, BLOCK_SIZE_BITS)
        t_temp = (B * (2 * B + 1)) & and_modulo
        t = ROL(t_temp, lgw, BLOCK_SIZE_BITS)
        tmod = t & (BLOCK_SIZE_BITS - 1)
        umod = u & (BLOCK_SIZE_BITS - 1)
        C = (ROR((C - secret[2 * i + 1]) & and_modulo, tmod, BLOCK_SIZE_BITS) ^ u)
        A = (ROR((A - secret[2 * i]) & and_modulo, umod, BLOCK_SIZE_BITS) ^ t)
    D = (D - secret[1]) & and_modulo
    B = (B - secret[0]) & and_modulo
    orgi = [A, B, C, D]
    return cipher, orgi


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


def gen_rc6_key(uk):
    r = 12
    w = 32
    b = len(uk)
    modulo = 2 ** 32
    s = (2 * r + 4) * [0]
    s[0] = 0xB7E15163
    for i in range(1, 2 * r + 4):
        s[i] = (s[i - 1] + 0x9E3779B9) % (2 ** w)
    encoded = blockConverter(uk)
    # print encoded
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


def rotems_main_verbose():
    # encrypt-decrypt a block of blocks
    # Now fit with Schnorr signature
    """
    Obtain input
    """
    sentence = input("Enter Sentence: ")
    # random "sentence" generator for testing
    # sentence = ''.join([chr(random.randint(ord('A'), ord('z')))
    #          for _ in range(random.randint(20, 45))])
    # sentence = ''.join([chr(ord('a') + i % 26) for i in range(10)])
    # split message to 128 bits blocks
    lst_of_sentences = [sentence[i:i + INPUT_SIZE_BYTES] for i in range(0, len(sentence), INPUT_SIZE_BYTES)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != INPUT_SIZE_BYTES:
            lst_of_sentences[i] = sent + ' ' * (INPUT_SIZE_BYTES - len(sent))

    print(f'Input:\t {sentence}')

    # generate keys for encryption (over the large [2048bits] prime field chosen in "constants.py")
    secret1, secret2 = generateKeys()
    # generate the Schnorr key (over the prime field defined in schnorr lib)
    sch_key = random.randint(0, schnorr_lib.n - 1)
    """
    Encrypt input
    """
    # for debug     , for decryption / to send
    secret1 = gen_rc6_key(str(secret1))
    e_whole_sentence, encrypted_blocks = encrypt_many_single_key(lst_of_sentences, secret1)

    """
    Get original message digest
    """
    message_hash_digest = hashlib.sha256(sentence.encode()).digest()
    print(f"Clear-text digest: {message_hash_digest}")
    private_key_as_hex_string = hex(sch_key)[2:]
    if len(private_key_as_hex_string) % 2:
        private_key_as_hex_string = '0' + private_key_as_hex_string
    print(f"{private_key_as_hex_string=}")

    """
    Sign message using Schnorr signature via private key (private_key_1)
    """
    sig = schnorr_lib.schnorr_sign(message_hash_digest, private_key_as_hex_string)
    print(f"Signature: {sig.hex()}")
    """
    Generate public key PROPERLY to with message
    """
    public_key = schnorr_lib.pubkey_gen_from_hex(private_key_as_hex_string)

    """
    Verify signature using public key
    """
    # get original message as bytes:
    msg_bytes = sentence.encode()
    # apply hash function
    hashed_message = hashlib.sha256(msg_bytes).digest()
    # verify
    result = schnorr_lib.schnorr_verify(hashed_message, public_key, sig)
    print(f"Signature verification result: {result}")
    tmp = e_whole_sentence.encode()
    print(f'Encrypted String (as binary): {tmp}')

    """
    Decrypt message
    """
    secret2 = gen_rc6_key(str(secret2))
    decrypted_text = decrypt_many_single_key(encrypted_blocks, secret2)
    try:
        assert decrypted_text[:len(sentence)] == sentence
    except AssertionError:
        print(f"ERROR - encryption-decryption process failed!\nsrc: {sentence}\ndest: {decrypted_text}",
              file=sys.stderr)
        exit(-1)

    print("\nDecrypted:\t", decrypted_text)


if __name__ == "__main__":
    # now calling my main (verbose)
    rotems_main_verbose()
