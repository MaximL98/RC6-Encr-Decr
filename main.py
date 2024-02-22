# Importing necessary modules and functions
import argparse, sys, math
from utils import print_fails # Importing a utility function for error handlin

from diffie_hellman import * # Importing Diffie-Hellman key exchange functions
from schnorr_lib import sha256, schnorr_sign, schnorr_musig_sign, schnorr_musig2_sign, schnorr_verify # Importing Schnorr signature functions

# Function to perform bitwise rotation to the right
def ROR(x, n, bits = 32):
    mask = (2**n) - 1 # Creating a mask to select the bits to be rotated
    mask_bits = x & mask # Applying the mask to get the bits to be rotated
    return (x >> n) | (mask_bits << (bits - n)) # Performing the rotation

# Function to perform bitwise rotation to the left
def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits) # Simply calling ROR with adjusted parameters

# Function to convert a sentence into blocks of binary, each block being  32 bits
def blockConverter(sentence):
    encoded = []  # List to store the binary blocks
    res = "" # Temporary string to hold the binary representation of each character
    for i in range(0,len(sentence)):
        if i%4==0 and i!=0 : # If the character is the  4th in the block
            encoded.append(res) # Append the current block to the list
            res = "" # Reset the temporary string
        temp = bin(ord(sentence[i]))[2:] # Convert the character to binary
        if len(temp) <8: # If the binary representation is less than  8 bits
            temp = "0"*(8-len(temp)) + temp # Pad with zeros
        res = res + temp # Append the binary representation to the temporary string
    encoded.append(res) # Append the last block
    return encoded # Return the list of binary blocks

# Function to convert a list of binary blocks back into a string
def deBlocker(blocks):
    s = "" # String to hold the final result
    for ele in blocks:
        temp =bin(ele)[2:] # Convert the integer to binary
        if len(temp) <32: # If the binary representation is less than  32 bits
            temp = "0"*(32-len(temp)) + temp # Pad with zeros
        for i in range(0,4): # For each character in the block
            s=s+chr(int(temp[i*8:(i+1)*8],2)) # Convert binary back to character and append to the string
    return s # Return the final string

# Function to generate keys for encryption and decryption
def generateKeys():
    # Code for generating keys using Diffie-Hellman key exchange
    # This includes getting user input for prime number and primitive root, 
    # checking their validity, and calculating public and private keys
    # Finally, it checks if the secret keys are the same for both users
    l = []
    while 1:
        P = int(input("Enter P : "))
        if prime_checker(P) == -1:
            print("Number Is Not Prime, Please Enter Again!")
            continue
        break
    
    while 1:
        G = int(input(f"Enter The Primitive Root Of {P} : "))
        if primitive_check(G, P, l) == -1:
            print(f"Number Is Not A Primitive Root Of {P}, Please Try Again!")
            continue
        break
    
    # Private Keys
    while 1:
        x1, x2 = int(input("Enter The Private Key Of User 1 (integer): ")), int(
            input("Enter The Private Key Of User 2 (integer): "))
        
        if x1 >= P or x2 >= P:
            print(f"Private Key Of Both The Users Should Be Less Than {P}!")
        else:
            break
        
    
    # Calculate Public Keys
    y1, y2 = pow(G, x1) % P, pow(G, x2) % P
    
    # Generate Secret Keys
    k1, k2 = pow(y2, x1) % P, pow(y1, x2) % P
    
    print(f"\nSecret Key For User 1 Is {k1}\nSecret Key For User 2 Is {k2}\n")
    
    if k1 == k2:
        print("Keys Have Been Exchanged Successfully")
    else:
        print("Keys Have Not Been Exchanged Successfully")
    
    return k1, k2, P, G

# Function to encrypt a sentence using a secret key
def encrypt(sentence, secret):
    # Code for encrypting a sentence by converting it to binary blocks, 
    # performing encryption operations, and returning the original and encrypted blocks
    encoded = blockConverter(sentence)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    #w=32
    modulo = 2**32
    lgw = 5
    B = (B + secret)%modulo
    D = (D + secret)%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + secret)%modulo 
        C = (ROL(C^u,tmod,32) + secret)%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + secret)%modulo 
    C = (C + secret)%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher

# Function to decrypt an encrypted sentence using a secret key
def decrypt(esentence, secret):
    # Code for decrypting an encrypted sentence by converting it back to binary blocks, 
    # performing decryption operations, and returning the decrypted blocks
    encoded = blockConverter(esentence)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r=12
    #w=32
    modulo = 2**32
    lgw = 5
    C = (C - secret)%modulo
    A = (A - secret)%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-secret)%modulo,tmod,32)  ^u)  
        A = (ROR((A-secret)%modulo,umod,32)   ^t) 
    D = (D - secret)%modulo 
    B = (B - secret)%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher,orgi


# Main function to execute the program
def main():
    # Code for getting user input, generating keys, 
    # encrypting and decrypting a sentence, and verifying the signature
    sentence = input("Enter Sentence (0-16 characters): ")
    sentence =sentence + " "*(16-len(sentence))
   
    secret1, secret2, P, G = generateKeys()
    sentence = sentence[:16]
    secret_keys = [secret1, secret2]

    ### SCHNORR SIGN STARTS HERE ###    
    # Signature
    try:
        # Get message digest
        M = sha256(sentence.encode())
        X = None

        sig = schnorr_sign(M, str(secret_keys[0]))

        print("> Message =", M.hex())
        print("> Signature =", sig.hex())
        if X is not None: 
            print("> Public aggregate=", X.hex())   
    except Exception as e:
            print_fails("[e] Exception:", e)
            sys.exit(2)
    ################################

    ### SCHNORR VERIFY ###
    try: 
        msg_bytes = sha256(sentence.encode())
        sig_bytes = bytes.fromhex(sig.hex())
        print(f"P.to_bytes(P.bit_length() + 7 // 8, 'big') = {P.to_bytes(P.bit_length() + 7 // 8, 'big')}")
        pubkey_bytes = P.to_bytes(P.bit_length() + 7 // 8, 'big')

        result = schnorr_verify(msg_bytes, pubkey_bytes, sig_bytes)
        print("\nThe signature is: ", sig)
        print("The public key is: ", P)
        print('The message digest is:', msg_bytes.hex())
        print("\nIs the signature valid for this message and this public key? ")
        if result:
            print_success("Yes")
        else:
            print_fails("No")
    except Exception as e:
        print_fails("[e] Exception:", e)
        sys.exit(2)

    ######################

    orgi,cipher = encrypt(sentence, secret1)
    esentence = deBlocker(cipher)
    
    print("Input:\t "+sentence) 

    print("\nOriginal String list: ",orgi)
    print("Length of Input String: ",len(sentence))
    
    print("\nEncrypted String list: ",cipher)
    print("Encrypted String: " + esentence)
    print("Length of Encrypted String: ",len(esentence))

    cipher,orgi = decrypt(esentence,secret2)
    sentence = deBlocker(orgi)
    print("\nDecrypted:\t",sentence)

if __name__ == "__main__":
	main() # Execute the main function if the script is run directly