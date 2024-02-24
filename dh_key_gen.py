import random

# Schnorr import
import schnorr_lib

# condition to use the 256bit prime from the schnorr library as both the DH prime and Schnorr prime.
USING_SCHNORR_PRIME_IN_DH = True
if USING_SCHNORR_PRIME_IN_DH:
    PRIME = schnorr_lib.p
    GENERATOR = 3


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


