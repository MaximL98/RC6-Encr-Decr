import random

import constants
# Schnorr import
import schnorr_lib

# condition to use the 256bit prime from the schnorr library as both the DH prime and Schnorr prime.
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
