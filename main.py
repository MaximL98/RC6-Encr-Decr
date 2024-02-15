import math
import sys
from diffie_hellman import *

#rotate right input x, by n bits
def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

#rotate left input x, by n bits
def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits)

#convert input sentence into blocks of binary
#creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for i in range(0,len(sentence)):
        if i%4==0 and i!=0 :
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) <8:
            temp = "0"*(8-len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded

#converts 4 blocks array of long int into string
def deBlocker(blocks):
    s = ""
    for ele in blocks:
        temp =bin(ele)[2:]
        if len(temp) <32:
            temp = "0"*(32-len(temp)) + temp
        for i in range(0,4):
            s=s+chr(int(temp[i*8:(i+1)*8],2))
    return s

#generate key s[0... 2r+3] from given input string userkey
'''generateKey(userkey)'''
def generateKeys():
    '''r=12
    w=32
    b=len(userkey)
    modulo = 2**32
    s=(2*r+4)*[0]
    s[0]=0xB7E15163
    for i in range(1,2*r+4):
        s[i]=(s[i-1]+0x9E3779B9)%(2**w)
    encoded = blockConverter(userkey)
    #print encoded
    enlength = len(encoded)
    l = enlength*[0]
    for i in range(1,enlength+1):
        l[enlength-i]=int(encoded[i-1],2)
    
    v = 3*max(enlength,2*r+4)
    A=B=i=j=0
    
    for index in range(0,v):
        A = s[i] = ROL((s[i] + A + B)%modulo,3,32)
        B = l[j] = ROL((l[j] + A + B)%modulo,(A+B)%32,32) 
        i = (i + 1) % (2*r + 4)
        j = (j + 1) % enlength
    return s'''
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
    
    return k1, k2

def encrypt(sentence, secret):
    encoded = blockConverter(sentence)
    #enlength = len(encoded)
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


def decrypt(esentence, secret):
    encoded = blockConverter(esentence)
    #enlength = len(encoded)
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





def main():

    #key = input("Enter Key (0-16 characters): ")
    sentence = input("Enter Sentence (0-16 characters): ")

    sentence =sentence + " "*(16-len(sentence))
    #key =key + " "*(16-len(key))

    #key = key[:16]
                         
    #print("Key:\t"+key) 
    #s = generateKeys(key)
    secret1, secret2 = generateKeys()
    sentence = sentence[:16]
    
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
	main()