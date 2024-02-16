import prime_helpers
"""
From Rotem :
I automated the prime, root and key generation process,
try to mess with the PRIME_BITS and PRIME_LEN consts in prime_helpers.py if this runs too slow,
values of 7,100 respectively should work fast enough (can reduce 100 by a bit, don't touch the 7).

Also, todo tell me if key range is too low, I set it between prime / 2 and prime-1 (so it's large), 
but maybe range should be larger as in (2, prime-1) 

Finally, TODO: maybe fix order? currently we get string first then create primes and keys, should this be the order?
"""


# rotate right input x, by n bits
def ROR(x, n, bits=32):
    mask = (2 ** n) - 1
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


def generateKeys():
    # auto generate prime and primitive (read prime helpers, sympy is required for root as it's too hard :) )
    P, G = prime_helpers.get_prime_and_primitive_root()
    print(f"Generated prime: {P} with primitive root {G}")

    # auto generate Private Keys
    p_range = (max(2, P//8), P-1)
    x1, x2 = prime_helpers.random.randint(*p_range), prime_helpers.random.randint(*p_range)
    print(f"Generated private keys: {x1=}, {x2=}")

    # Calculate Public Keys:
    # Rotem "fixed" this, in python pow is capable of doing a^b mod c if used with 3 args,
    # the whole op stays in C and is faster
    y1, y2 = pow(G, x1, P), pow(G, x2, P)

    # Generate Secret Keys
    k1, k2 = pow(y2, x1, P), pow(y1, x2, P)
    print(f"\nSecret Key For User 1 Is {k1}\nSecret Key For User 2 Is {k2}\n")

    if k1 == k2:
        print("Keys Have Been Exchanged Successfully")
    else:
        print("Keys Have Not Been Exchanged Successfully")

    return k1, k2


def encrypt(sentence, secret):
    encoded = blockConverter(sentence)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    orgi = [A, B, C, D]
    r = 12
    modulo = 2 ** 32
    lgw = 5
    B = (B + secret) % modulo
    D = (D + secret) % modulo
    for i in range(1, r + 1):
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        A = (ROL(A ^ t, umod, 32) + secret) % modulo
        C = (ROL(C ^ u, tmod, 32) + secret) % modulo
        (A, B, C, D) = (B, C, D, A)
    A = (A + secret) % modulo
    C = (C + secret) % modulo
    cipher = [A, B, C, D]
    return orgi, cipher


def decrypt(esentence, secret):
    encoded = blockConverter(esentence)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r = 12
    modulo = 2 ** 32
    lgw = 5
    C = (C - secret) % modulo
    A = (A - secret) % modulo
    for j in range(1, r + 1):
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        C = (ROR((C - secret) % modulo, tmod, 32) ^ u)
        A = (ROR((A - secret) % modulo, umod, 32) ^ t)
    D = (D - secret) % modulo
    B = (B - secret) % modulo
    orgi = [A, B, C, D]
    return cipher, orgi


def main():
    sentence = input("Enter Sentence (0-16 characters): ")

    sentence = sentence + " " * (16 - len(sentence))

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
    main()
