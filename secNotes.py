'''
    @author Matteo Gianvenuti https://github.com/mqtth3w
    @license MIT License
'''

from Crypto.Cipher import AES
from hashlib import sha3_512
import tkinter as tk
from tkinter import filedialog, messagebox

def pad(data:bytes, blockSize:int) -> bytes:
    padLen = blockSize - (len(data) % blockSize)
    return data + (bytes([padLen]) * padLen)

def unpad(data:bytes, blockSize:int) -> bytes:
    return data[:-ord(data[-1:])]

def encrypt_AES256(KEY:bytes, plaintext:str) -> bytes:
    plaintext = plaintext.encode()
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 16))

def decrypt_AES256(KEY:bytes, ciphertext:bytes) -> str:
    cipher = AES.new(KEY, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, 16).decode()

def calculate_sha3_512(input_string:str) -> str:
    sha3_512_hash = sha3_512()
    sha3_512_hash.update(input_string.encode('utf-8'))
    return sha3_512_hash.hexdigest()

def select_file(entry):
    selected_file = filedialog.askopenfilename()
    if selected_file:
        entry.delete(0, 'end')
        entry.insert(0, selected_file)
        
def encrypt(aesKey, iv, hashKey, file, text):
    if len(aesKey) != 32 or not iv or not hashKey or not file or not text:
        messagebox.showerror("Error", "AES key must be 32 characters long. AES Key, IV (CBC), hash Key, file path and textbox cannot be empty.")
    else:
        chipertext = encrypt_AES256(aesKey.encode(), text)

def decrypt(aesKey, iv, hashKey, file, text):
    if len(aesKey) != 32 or not iv or not hashKey or not file or not text:
        messagebox.showerror("Error", "AES key must be 32 characters long. AES Key, IV (CBC), hash Key, file path and textbox cannot be empty.")
    else:
        pass

def check_intergity(text, hashKey):
    pass

def secNotes_gui():
    global root, result_text
    root = tk.Tk()
    root.title("secNotes by Mqtth3w")
    root.resizable(False, False)
    
    tk.Label(root, text="Symmetric key (AES):").grid(row=0, column=0)
    aesKey_entry = tk.Entry(root, width=50)
    aesKey_entry.grid(row=0, column=1)
    
    tk.Label(root, text="IV (AES CBC mode):").grid(row=1, column=0)
    iv_entry = tk.Entry(root, width=50)
    iv_entry.grid(row=1, column=1)
    
    tk.Label(root, text="Checksum key:").grid(row=2, column=0)
    hashKey_entry = tk.Entry(root, width=50)
    hashKey_entry.grid(row=2, column=1)
    
    tk.Label(root, text="Path to the encrypted file:").grid(row=3, column=0)
    file_entry = tk.Entry(root, width=50)
    file_entry.grid(row=3, column=1)
    tk.Button(root, text="Browse", command=lambda: select_file(file_entry)).grid(row=3, column=2)

    tk.Label(root, text="The content of the following textbox will be encrypted in the specified \n"
                    "file with the given keys. To decrypt the specified file, you need \n"
                    "to use the same encryption keys. Please wait. \n").grid(row=5, columnspan=3)

    tk.Button(root, text="Encrypt", command=lambda: encrypt(aesKey_entry.get(),
        iv_entry.get(), hashKey_entry.get(), file_entry.get(), result_text.get("1.0", tk.END)
        )).grid(row=6, column=0)
    
    tk.Button(root, text="Decrypt and check integrity", command=lambda: decrypt(aesKey_entry.get(),
        iv_entry.get(), hashKey_entry.get(), file_entry.get(), result_text.get("1.0", tk.END)
        )).grid(row=6, column=1)
    
    result_text = tk.Text(root, width=100, height=30)
    result_text.grid(row=7, column=0, columnspan=3)

    root.mainloop()


if __name__ == "__main__":
    secNotes_gui()
