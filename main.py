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

JSONfilenameArray = ["SentenceToSend", "SecretKeys", "EncryptedSentence", "Schnorr_get_message_digest", "Schnorr_sign_via_private_key", "Public_Key", "DecryptedSentence", "PublicKeys"]
JSONfilenameArrayAck = ["SentenceToSendAck", "SecretKeysAck", "EncryptedSentenceAck", "Schnorr_get_message_digestAck", "Schnorr_sign_via_private_keyAck", "Public_KeyAck", "DecryptedSentenceAck", "PublicKeysAck"]

# split message to 128 bits blocks
def split_sentence(sentence):
    lst_of_sentences = [sentence[i:i + 16] for i in range(0, len(sentence), 16)]
    for i, sent in enumerate(lst_of_sentences):
        if len(sent) != 16:
            lst_of_sentences[i] = sent + ' ' * (16 - len(sent))
    print(f'Input:\t {sentence}')
    return lst_of_sentences

# Create a JSON file to store the information as strings, for the sake of clean presentation
def createJSONFile(dictionary, index, isAck):
    # Create a JSON file to store the keys
    if not isAck:
        jsonFileName = "./Gui/JSONFiles/" + JSONfilenameArray[index] + ".json"
    else:
        jsonFileName = "./Gui/JSONFiles/" + JSONfilenameArrayAck[index] + ".json"
    
    
    json_object = json.dumps(dictionary, indent = 4)
    
    with open(jsonFileName, 'w') as outfile:
        outfile.write(json_object)
        
def generateJSONFiles(sentence, e_whole_sentence, encrypted_blocks, message_hash_digest, private_key_as_hex_string, sig, public_key, isAck):
    
    print("sentence: ", sentence)
    dict = {"Sentence": sentence}
    createJSONFile(dict, 0, isAck)
    dict = {"EncryptedSentence": f"`{e_whole_sentence.encode()}`", "EncryptedBlocks": encrypted_blocks}
    createJSONFile(dict, 2, isAck)
    dict = {"message_hash_digest": message_hash_digest.hex(), "private_key_as_hex_string": private_key_as_hex_string}
    createJSONFile(dict, 3, isAck)
    dict = {"Signature": sig.hex()}
    createJSONFile(dict, 4, isAck)
    dict = {"public_key": public_key.hex()}
    createJSONFile(dict, 5, isAck)

def sign_dh_keys(isAck):
    # generate keys for encryption (over the large prime field chosen in "constants.py")
    # From Rotem:
    """
    I assume this next line is supposed to be the safe-channel, as in the operation where the user
    and the bank swap the DH keys, since this is the only call in the file.
    I hope you didn't delete it as the file changed drastically.
    """
    # secret1, secret2 = generateKeys()
    # user generates random key
    user_private_key = generateDiffieHellmanPrivateKey()
    # user calculates public key
    user_pub_key = generateDiffieHellmanPublicKey(user_private_key)
    # bank sends public key to user (we keep bank private key here since we have no real server)
    bank_private_key, bank_public_key = sendDiffieHellmanPublicKeyToUser()
    # simulates the fact that now both bank and user have the dh key
    bank_diffie_hellman_key = user_diffie_hellman_key = pow(bank_public_key, user_private_key, PRIME)
    validated = validateDiffieHellmanKey(user_diffie_hellman_key, bank_private_key, user_pub_key)
    if not validated:
        print(f"Error! Failed to create user-bank secure channel, DH keys are not equal", file=sys.stderr)
        exit(-1)

    sch_key_for_key = schnorr_lib.sch_key_gen()
    pk_hash_digest = schnorr_lib.msg_hash_digest(str(user_diffie_hellman_key))
    private_key_as_hex_string_for_key = schnorr_lib.get_hex_private_key(sch_key_for_key)
    sig = schnorr_lib.schnorr_sign(pk_hash_digest, private_key_as_hex_string_for_key)
    public_key_dh = schnorr_lib.pubkey_gen_from_hex(private_key_as_hex_string_for_key)
    ### @ ME (maxim)
    ##############################################GUI################################################
    dict = {"secret1": str(user_diffie_hellman_key), "secret2": str(bank_diffie_hellman_key), "sch_key": str(sch_key_for_key)}
    createJSONFile(dict, 1, isAck)
    dict = {"user_public_key": str(user_pub_key), "bank_public_key": str(bank_public_key)}
    createJSONFile(dict, 7, isAck)
    ##############################################GUI################################################
    return user_diffie_hellman_key, sig, pk_hash_digest, public_key_dh

def check_dh_key_sign(pk_hash_digest, public_key, sig_for_key):
    return schnorr_lib.schnorr_verify(pk_hash_digest, public_key, sig_for_key)
    

# Moved encr + sig logic from main into function to avoid code duplication 
def send_encr_msg(secret1, isAck, sentence = None):
    if sentence == None:
        sentence = input("Enter Sentence: ")
    lst_of_sentences = split_sentence(sentence)
    ## Cmd will be encr + sig and sent to BANK:

    
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
    
    ##############################################GUI################################################
    generateJSONFiles(sentence, e_whole_sentence, encrypted_blocks, message_hash_digest, private_key_as_hex_string, sig, public_key, isAck)
    ##############################################GUI################################################
    
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
    else:
        print("I dont know you, you are not the original user! payment canceled!")
        
    return decrypted_text
        
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

    secret1, sig_for_key, pk_hash_digest, public_key_dh = sign_dh_keys(isAck = False)
    message_hash_digest, public_key, sig, encrypted_blocks, sentence, e_whole_sentence = send_encr_msg(secret1, False, None)
    ### END OF USER SIDE, cmd now been sent to BANK

    ### BANK SIDE, verify sig and if good, decrypt cmd
    decrypted_text = msg_decr(message_hash_digest, public_key, sig, encrypted_blocks, secret1, sentence, e_whole_sentence, sig_for_key, pk_hash_digest, public_key_dh)
    createJSONFile({"DecryptedSentence": decrypted_text}, 6, False)

    ## BANK SEND ACK ##
    print("Pending Bank Approval...")
    secret1, sig_for_key, pk_hash_digest, public_key_dh = sign_dh_keys(isAck = True)
    message_hash_digest, public_key, sig, encrypted_blocks, sentence, e_whole_sentence = send_encr_msg(secret1, True, "Successful Payment")

    ### USER SIDE, verify sig and if good, decrypt cmd
    decrypted_text = msg_decr(message_hash_digest, public_key, sig, encrypted_blocks, secret1, sentence, e_whole_sentence, sig_for_key, pk_hash_digest, public_key_dh)

    createJSONFile({"DecryptedSentence": decrypted_text}, 8, True)
    ## TODO: 
    # 1. Bank will carry out the cmd (if legal cmd)
    # 2. Will send back (encr?) msg that cmd was completed successfully
    ## END?



if __name__ == "__main__":
    # now calling my main (verbose)
    main()