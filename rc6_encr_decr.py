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