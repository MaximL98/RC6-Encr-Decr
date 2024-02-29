import sys

import db_control
from rc6_encr_decr import *
from dh_key_gen import *

"""
From Rotem :
- Check if our keys are defined properly (we use the key from DH in RC6)
- Weak keys? other security issues?
"""


# split message to 128 bits blocks
def split_sentence(sentence):
    lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != 16:
            lst_of_sentences[i] = sent + ' ' * (16 - len(sent))
    print(f'Input:\t {sentence}')
    return lst_of_sentences


def rotems_main_verbose():
    # encrypt-decrypt a block of blocks
    # Now fit with Schnorr signature

    ### USE CASE EXAMPLE ###
    ## User input data (in GUI?) ## 
    ## Passcode will be hashed and checked in db if correct data (db_control?)##
    ## User then can send cmd by: 
    """
    Obtain input
    """
    sentence = input("Enter Sentence: ")
    lst_of_sentences = split_sentence(sentence)
    ## Cmd will be encr + sig and sent to BANK:

    # generate keys for encryption (over the large prime field chosen in "constants.py")
    secret1, secret2 = generateKeys()

    # generate the Schnorr key (over the prime field defined in schnorr lib)
    sch_key = schnorr_lib.sch_key_gen()

    """
    Encrypt input
    """
    # for debug     , for decryption / to send
    e_whole_sentence, encrypted_blocks = encrypt_many_single_key(lst_of_sentences, secret1)

    """
    Schnorr sig get original message digest
    """
    message_hash_digest = schnorr_lib.msg_hash_digest(sentence)
    private_key_as_hex_string = schnorr_lib.get_hex_private_key(sch_key)

    """
    Sign message using Schnorr signature via private key (private_key_1)
    """
    sig = schnorr_lib.schnorr_sign(message_hash_digest, private_key_as_hex_string)
    print(f"Signature: {sig.hex()}")
    """
    Generate public key PROPERLY to with message
    """
    public_key = schnorr_lib.pubkey_gen_from_hex(private_key_as_hex_string)

    ### END OF USER SIDE, cmd now been sent to BANK

    ### BANK SIDE, verify sig and if good, decrypt cmd
    """
    Verify signature using public key
    """
    # NO NEED FOR THIS
    '''# get original message as bytes:
    msg_bytes = sentence.encode()
    # apply hash function
    hashed_message = hashlib.sha256(msg_bytes).digest()'''

    # Verify sig
    result = schnorr_lib.schnorr_verify(message_hash_digest, public_key, sig)
    print(f"Signature verification result: {result}")
    tmp = e_whole_sentence.encode()
    print(f'Encrypted String (as binary): {tmp}')
    # If sig is good, decrypt cmd
    if result:
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

    else:
        print("I dont know you, you are not the original user!")

    ## TODO: 
    # 1. Bank will carry out the cmd (if legal cmd)
    # 2. Will send back (encr?) msg that cmd was completed successfully
    ## END?


if __name__ == "__main__":
    # now calling my main (verbose)
    rotems_main_verbose()
