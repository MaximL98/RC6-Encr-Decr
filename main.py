import random
import sys
# hash imports
import hashlib
# Schnorr import
import schnorr_lib

# import prime_helpers
from constants import *
"""
From Rotem :
Now prime and generator are both given, and keys are randomly generated in range of prime // 2 to prime (roughly).
TODO - define proper process to weed out weak keys.

from Rotem new:
Schnorr signature now (probably) works, I changed the following
- changed the original encryption prime to the one in schnorr-lib, and set the generator to 3 (as it is).
- the signature is calculated over the digest (by the sender), using the same private key as the one he used to 
encrpyt the message (maybe this is not ideal?)
- the signature is then generated
- the verification process required a proper public key, NOT P (not the prime!), but the output of the
"pubkey_gen_from_hex(private_key)" function! (you could use the int variant but since we convert to hex 
during the signing process I just called this one.
- Now, call verify as such: schnorr_verify(digest, public_key, sig) and get True since the math does work

Our mistake was using improper public key.
Maybe my mistake now is to use the same keyspace for all 3 components (DH, RC6 and Schnorr) but that's TBDiscussed.
Enjoy.

"""

# condition to use the 256bit prime from the schnorr library as both the DH prime and Schnorr prime.
USING_SCHNORR_PRIME_IN_DH = True
if USING_SCHNORR_PRIME_IN_DH:
    PRIME = schnorr_lib.p
    GENERATOR = 3


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
       creates 4 blocks of binary each of 32 bits."""
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


def deBlocker(blocks):
    """converts 4 blocks array of long int into string"""
    s = ""
    for ele in blocks:
        temp = bin(ele)[2:]
        # print(f"deBlocker working on element {temp}\n",file=sys.stderr)
        if len(temp) < 32:
            temp = "0" * (32 - len(temp)) + temp
        for i in range(0, 4):
            # print(f"Appending to {s}: {s} + {chr(int(temp[i * 8:(i + 1) * 8], 2))=}")
            s = s + chr(int(temp[i * 8:(i + 1) * 8], 2))
    # print(f"Input:\n{blocks}\nOutput:\n{s}")
    return s


def get_safe_key(prime):
    """Get odd key between prime // 2 and prime - 1"""
    # not safe yet, but huge range for keys
    # for n bit prime, we get n - 1 bits of keyspace (in current version, 2047 bits)
    k=random.randint((prime-1) // 2, (prime - 1))
    if not k & 1:
        k -= 1
    return k


def generateKeys():
    """Returns both secret keys AFTER THE EXCHANGE.
     TODO: simulate the actual exchange, remember that this function returns identical keys, NOT PRIVATE KEYS"""
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

    # split message to 128 bits blocks
    lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != 16:
            lst_of_sentences[i] = sent + ' ' * (16 - len(sent))

    print(f'Input:\t {sentence}')

    # generate keys for encryption (over the large prime field chosen in "constants.py")
    secret1, secret2 = generateKeys()
    # generate the Schnorr key (over the prime field defined in schnorr lib)
    sch_key = random.randint(0, schnorr_lib.n - 1)
    """
    Encrypt input
    """
    # for debug     , for decryption / to send
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
