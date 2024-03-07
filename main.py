import sys

import db_control
from rc6_encr_decr import *
from dh_key_gen import *

import json

"""
From Rotem :
- Check if our keys are defined properly (we use the key from DH in RC6)
- Weak keys? other security issues?
"""

JSONfilenameArray = ["SentenceToSend", "SecretKeys", "EncryptedSentence", "Schnorr_get_message_digest", "Schnorr_sign_via_private_key", "Public_Key", "DecryptedSentence"]

# split message to 128 bits blocks
def split_sentence(sentence):
    lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != 16:
            lst_of_sentences[i] = sent + ' ' * (16 - len(sent))
    print(f'Input:\t {sentence}')
    return lst_of_sentences

# Create a JSON file to store the information as strings, for the sake of clean presentation
def createJSONFile(dictionary, index):
    # Create a JSON file to store the keys
    
    jsonFileName = "./Gui/JSONFiles/" + JSONfilenameArray[index] + ".json"
    
    json_object = json.dumps(dictionary, indent = 4)
    
    with open(jsonFileName, 'w') as outfile:
        outfile.write(json_object)

def sign_dh_keys():
    # generate keys for encryption (over the large prime field chosen in "constants.py")
    secret1, secret2 = generateKeys()
    

    sch_key_for_key = schnorr_lib.sch_key_gen()
    pk_hash_digest = schnorr_lib.msg_hash_digest(str(secret1))
    private_key_as_hex_string_for_key = schnorr_lib.get_hex_private_key(sch_key_for_key)
    sig = schnorr_lib.schnorr_sign(pk_hash_digest, private_key_as_hex_string_for_key)
    public_key_dh = schnorr_lib.pubkey_gen_from_hex(private_key_as_hex_string_for_key)
    ### @ ME (maxim)
    ##############################################GUI################################################
    dict = {"secret1": str(secret1), "secret2": str(secret2), "sch_key": str(sch_key_for_key)}
    createJSONFile(dict, 1)
    ##############################################GUI################################################
    return secret1, sig, pk_hash_digest, public_key_dh

def check_dh_key_sign(pk_hash_digest, public_key, sig_for_key):
    return schnorr_lib.schnorr_verify(pk_hash_digest, public_key, sig_for_key)
    

# Moved encr + sig logic from main into function to avoid code duplication 
def send_encr_msg(secret1, sentence = None):
    if sentence == None:
        sentence = input("Enter Sentence: ")
    lst_of_sentences = split_sentence(sentence)
    ## Cmd will be encr + sig and sent to BANK:
    ##############################################GUI################################################
    dict = {"sentence": sentence}
    createJSONFile(dict, 0)
    ##############################################GUI################################################
    
    # generate the Schnorr key (over the prime field defined in schnorr lib)
    sch_key = schnorr_lib.sch_key_gen()

    ## CHANGE NEED HERE!
    '''##############################################GUI################################################
    dict = {"secret1": str(secret1), "secret2": str(secret2), "sch_key": str(sch_key)}
    createJSONFile(dict, 1)
    ##############################################GUI################################################'''

    """
    Encrypt input
    """
    # for debug     , for decryption / to send
    e_whole_sentence, encrypted_blocks = encrypt_many_single_key(lst_of_sentences, secret1)
    ##############################################GUI################################################
    dict = {"EncryptedSentence": f"`{e_whole_sentence.encode()}`", "EncryptedBlocks": encrypted_blocks}
    createJSONFile(dict, 2)
    ##############################################GUI################################################
    """
    Schnorr sig get original message digest
    """
    message_hash_digest = schnorr_lib.msg_hash_digest(sentence)
    private_key_as_hex_string = schnorr_lib.get_hex_private_key(sch_key)
    
    ##############################################GUI################################################
    dict = {"message_hash_digest": message_hash_digest.hex(), "private_key_as_hex_string": private_key_as_hex_string}
    createJSONFile(dict, 3)
    ##############################################GUI################################################
    """
    Sign message using Schnorr signature via private key (private_key_1)
    """
    sig = schnorr_lib.schnorr_sign(message_hash_digest, private_key_as_hex_string)
    print(f"Signature: {sig.hex()}")
    ##############################################GUI################################################
    dict = {"Signature": sig.hex()}
    createJSONFile(dict, 4)
    ##############################################GUI################################################
    """
    Generate public key PROPERLY to with message
    """
    public_key = schnorr_lib.pubkey_gen_from_hex(private_key_as_hex_string)
    ##############################################GUI################################################
    dict = {"public_key": public_key.hex()}
    createJSONFile(dict, 5)
    
    return message_hash_digest, public_key, sig, encrypted_blocks, sentence, e_whole_sentence

# Moved decr + sig check logic from main into function to avoid code duplication 
def msg_decr(message_hash_digest, public_key, sig, encrypted_blocks, secret1, sentence, e_whole_sentence, sig_for_key, pk_hash_digest, public_key_dh):
    """
    Verify signature using public key
    """
    result_dh_sig = schnorr_lib.schnorr_verify(pk_hash_digest, public_key_dh, sig_for_key)
    print(f"Signature key verification result: {result_dh_sig}")
    # Verify sig
    result = schnorr_lib.schnorr_verify(message_hash_digest, public_key, sig)
    print(f"Signature verification result: {result}")
    tmp = e_whole_sentence.encode()
    print(f'Encrypted String (as binary): {tmp}')
    # If sig is good, decrypt cmd
    if result and result_dh_sig:
        """
        Decrypt message
        """
        decrypted_text = decrypt_many_single_key(encrypted_blocks, secret1)
        try:
            assert decrypted_text[:len(sentence)] == sentence
        except AssertionError:
            print(f"ERROR - encryption-decryption process failed!\nsrc: {sentence}\ndest: {decrypted_text}",
                    file=sys.stderr)
            exit(-1)
        print("\nDecrypted:\t", decrypted_text)
        createJSONFile({"DecryptedSentence": decrypted_text}, 6)
    else:
        print("I dont know you, you are not the original user! payment canceled!")
        
# Main function
def main():
    # encrypt-decrypt a block of blocks
    # Now fit with Schnorr signature

    ### USE CASE EXAMPLE ###
    ## User input data ## 

    while True:
        exists, first_name, last_name = db_control.check_exist()
        if(exists):
            if(db_control.check_cred(first_name, last_name)):
                print("User verification was successful")
                break
            else:
                print("Bad Credentials")
        else:
            print("User Not Found! Wrong input.")

    secret1, sig_for_key, pk_hash_digest, public_key_dh = sign_dh_keys()
    message_hash_digest, public_key, sig, encrypted_blocks, sentence, e_whole_sentence = send_encr_msg(secret1)
    ### END OF USER SIDE, cmd now been sent to BANK

    ### BANK SIDE, verify sig and if good, decrypt cmd
    msg_decr(message_hash_digest, public_key, sig, encrypted_blocks, secret1, sentence, e_whole_sentence, sig_for_key, pk_hash_digest, public_key_dh)

    ## BANK SEND ACK ##
    print("Pending Bank Approval...")
    secret1, sig_for_key, pk_hash_digest, public_key_dh = sign_dh_keys()
    message_hash_digest, public_key, sig, encrypted_blocks, sentence, e_whole_sentence = send_encr_msg(secret1,"Successful Payment")

    ### USER SIDE, verify sig and if good, decrypt cmd
    msg_decr(message_hash_digest, public_key, sig, encrypted_blocks, secret1, sentence, e_whole_sentence, sig_for_key, pk_hash_digest, public_key_dh)

    ## TODO: 
    # 1. Bank will carry out the cmd (if legal cmd)
    # 2. Will send back (encr?) msg that cmd was completed successfully
    ## END?



if __name__ == "__main__":
    # now calling my main (verbose)
    main()