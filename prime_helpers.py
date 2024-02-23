"""
NOT IN USE (prime and generator are taken from constants.py)
"""
import random
import sys
from math import log2

PRIME_BITS = 1024
try:
    import sympy

    primitive_root_finder = sympy.primitive_root
except ModuleNotFoundError:
    print("The application requires the module 'sympy' to be installed. Exiting . . .", file=sys.stderr)
    exit(-1)

# Pre generated primes
FIRST_PRIMES_LIST = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]


def nBitRandom(n):
    # get a number within n-1 to n bits
    return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)


def getLowLevelPrime(n):
    """Generate a prime candidate divisible
    by first primes"""
    while True:
        # Obtain a random number
        pc = nBitRandom(n)

        # Test divisibility by pre-generated
        # primes
        for divisor in FIRST_PRIMES_LIST:
            if pc % divisor == 0 and divisor ** 2 <= pc:
                break
        else:
            return pc


def isMillerRabinPassed(mrc, trial_number=100):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc - 1
    while ec & 1:  # attempt to slightly speed it up, used to be ec % 2 == 0
        ec >>= 1
        maxDivisionsByTwo += 1

    # assert is slightly costly?
    # assert (2 ** maxDivisionsByTwo * ec == mrc - 1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2 ** i * ec, mrc) == mrc - 1:
                return False
        return True

    # Set number of trials here
    numberOfRabinTrials = trial_number
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True


def get_likely_prime():
    # at 100 trials, the probability for primality is greater than 1 - (2^-100)
    while True:
        x = getLowLevelPrime(nBitRandom(PRIME_BITS))
        if isMillerRabinPassed(x, 100):
            return x


def get_prime_and_primitive_root():
    # prime = get_likely_prime()
    prime = sympy.nextprime(getLowLevelPrime(PRIME_BITS))
    return prime, primitive_root_finder(prime)


def fast_primitive_root(prime):
    # get random number between 2 and prime-1
    while True:
        r = random.randrange(2, (prime - 2))
        if pow(r, (prime - 1) >> 1, prime) != 1:
            return r


def get_prime_and_primitive_root_experimental():
    prime = sympy.nextprime(getLowLevelPrime(PRIME_BITS))
    return prime, fast_primitive_root(prime)

# dead code - TODO remove

# def rotems_main():
#     # an attempt to encrypt-decrypt a block of blocks
#     sentence = input("Enter Sentence: ")
#     # random "sentence" generator for testing
#     # sentence = ''.join([chr(random.randint(ord('A'), ord('z')))
#     #          for _ in range(random.randint(20, 45))])
#
#     # split message to 128 bits blocks
#     lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
#     for i, sent in enumerate(lst_of_sentences):
#         if len(sent) != 16:
#             lst_of_sentences[i] = sent + ' ' * (16 - len(sent))
#
#     print(f'Input:\t {sentence}')
#
#     secret1, secret2, _ = generateKeys()
#
#     # for debug     , for decryption / to send
#     e_whole_sentence, encrypted_blocks = encrypt_many_single_key(lst_of_sentences, secret1)
#
#     tmp = e_whole_sentence.encode()
#     print(f'Encrypted String (as binary): {tmp}')
#
#     decrypted_text = decrypt_many_single_key(encrypted_blocks, secret2)
#     try:
#         assert decrypted_text[:len(sentence)] == sentence
#     except AssertionError:
#         print(f"ERROR - encryption-decryption process failed!\nsrc: {sentence}\ndest: {decrypted_text}",
#               file=sys.stderr)
#         exit(-1)
#
#     print("\nDecrypted:\t", decrypted_text)
#
#
#
# def main():
#     sentence = input("Enter Sentence (0-16 characters): ")
#
#     sentence = sentence + " " * max(0, (16 - len(sentence)))
#     secret1, secret2 = generateKeys()
#     sentence = sentence[:16]
#
#     orgi, cipher = encrypt(sentence, secret1)
#     esentence = deBlocker(cipher)
#
#     print("Input:\t " + sentence)
#
#     print("\nOriginal String list: ", orgi)
#     print("Length of Input String: ", len(sentence))
#
#     print("\nEncrypted String list: ", cipher)
#     print("Encrypted String: " + esentence)
#     print("Length of Encrypted String: ", len(esentence))
#
#     cipher, orgi = decrypt(esentence, secret2)
#     sentence = deBlocker(orgi)
#     print("\nDecrypted:\t", sentence)
