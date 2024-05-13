from Crypto.Cipher import AES
from hashlib import sha3_512
from sys import exit as sysexit

ENOTE = "Enote.txt"
NNOTE = "Nnote.txt"

def pad(data:bytes, blockSize:int) -> bytes:
    padLen = blockSize - (len(data) % blockSize)
    return data + (bytes([padLen])*padLen)

def unpad(data:bytes, blockSize:int) -> bytes:
    return data[:-ord(data[-1:])]

def encrypt_AES256(plaintext:str) -> bytes:
    plaintext = plaintext.encode()
    cipher = AES.new(KEY_32, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext,16))

def decrypt_AES256(ciphertext:bytes) -> str:
    cipher = AES.new(KEY_32, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext,16).decode()

def calculate_sha3_512(input_string:str) -> str:
    sha3_512_hash = sha3_512()
    sha3_512_hash.update(input_string.encode('utf-8'))
    return sha3_512_hash.hexdigest()

def print_er(error:str):
    print(error)
    sysexit(1)

KEY_32 = input("password: ").encode()
match input("mode: "):
    case "read":
        try:
            with open(ENOTE, "rb") as f1:
                ciphertext = f1.read()
            plaintext = decrypt_AES256(ciphertext)
            print(plaintext)
        except:
            print_er("read error")
    case "append":
        try:
            with open(NNOTE, "r") as f2:
                plaintext = f2.read()
            ciphertext = encrypt_AES256(plaintext)
            with open(ENOTE, "ab") as f3:
                f3.write(ciphertext)
        except:
            print_er("append error")
    case _ :
        print_er("Bad mode")

