# if sympy is not allowed, call here to generate probable prime
import random
import sys
from math import log2

try:
    import sympy
    primitive_root_finder = sympy.primitive_root
except ModuleNotFoundError:
    print("The application requires the module 'sympy' to be installed. Exiting . . .", file=sys.stderr)
    exit(-1)


# some consts
PRIME_BITS = 7
PRIME_LEN = 100
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
    '''Generate a prime candidate divisible
    by first primes'''
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
    # 1024 bit is still logjam prone but slightly less so (ideally 2048 bit)
    # but we only use 100 bits since primitive root algorithm is still too inefficient
    # at 100 trials, the probability for primality is greater than 1 - (2^-100)
    # currently takes ~20ms on my (Rotem's) PC to generate a 100 bit prime on average
    # (using 1024 bits increases time by many orders of magnitude, but the main issue is finding a primitive root
    # \ subgroup generator, which currently takes a very long time)
    while True:
        x = getLowLevelPrime(nBitRandom(PRIME_BITS))
        if isMillerRabinPassed(x, 100) and log2(x) >= PRIME_LEN:
            return x


def get_prime_and_primitive_root():
    prime = get_likely_prime()
    return prime, primitive_root_finder(prime)

# TODO: later:
# def get_safe_prime():
#     while True:
#         factor1 = get_likely_prime()
#         p = 2*factor1 + 1
#         if isMillerRabinPassed(p, 20):
#             return p


# from tqdm import tqdm
# for _ in tqdm(range(1000)):
#     y = sympy.primitive_root(get_likely_prime())
#     print(y)

# print(get_prime_and_primitive_root())
