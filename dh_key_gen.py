import random

import constants
# Schnorr import
import schnorr_lib

# condition to use the 256bit prime from the schnorr library as both the DH prime and Schnorr prime.
# Rotem 8/3: modified to not use the same prime, back to using my large one
USING_SCHNORR_PRIME_IN_DH = False
if USING_SCHNORR_PRIME_IN_DH:
    PRIME = schnorr_lib.p
    GENERATOR = 3
else:
    PRIME = constants.PRIME
    GENERATOR = constants.GENERATOR


def get_safe_key(prime):
    """Get odd key between prime // 2 and prime - 1"""
    # not safe yet, but huge range for keys
    # for n bit prime, we get n - 1 bits of keyspace (in current version, 2047 bits)
    k = random.randint((prime - 1) // 2, (prime - 1))
    if not k & 1:
        k -= 1
    return k


def generateDiffieHellmanPrivateKey():
    return get_safe_key(PRIME)


def generateDiffieHellmanPublicKey(private_key):
    return pow(GENERATOR, private_key, PRIME)


def validateDiffieHellmanPublicKey(caller_private_key, public_key_received):
    return pow(public_key_received, caller_private_key, PRIME)


def compareDiffieHellmanKeys(k1, k2):
    return k1 == k2


def sendDiffieHellmanPublicKeyToUser():
    """This segment is the simulation of the bank's system processing the public key to create secure channel"""
    bank_private_key = generateDiffieHellmanPrivateKey()
    # bank sends public key to user
    return bank_private_key, pow(GENERATOR, bank_private_key, PRIME)

def validateDiffieHellmanKey(dh_key, bank_private_key, user_pub_key):
    # validate that dh_key is the same as user_pub_key ^ bank_private_key
    bank_dh_key = validateDiffieHellmanPublicKey(bank_private_key, user_pub_key)
    return compareDiffieHellmanKeys(dh_key, bank_dh_key)


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
