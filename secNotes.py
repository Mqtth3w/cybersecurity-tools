'''
    @author Matteo Gianvenuti https://github.com/mqtth3w
    @license GPL-3.0
'''

from Crypto.Cipher import AES
from hashlib import sha3_512
import os
import tkinter as tk
from tkinter import filedialog, messagebox

def pad(data: bytes, blockSize: int) -> bytes:
    padLen = blockSize - (len(data) % blockSize)
    return data + (bytes([padLen]) * padLen)

def unpad(data: bytes, blockSize: int) -> bytes:
    return data[:-ord(data[-1:])]

def encrypt_AES256(KEY: bytes, IV: bytes, plaintext: str) -> bytes:
    plaintext = plaintext.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt_AES256(KEY: bytes, IV: bytes, ciphertext: bytes) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size).decode()

def calculate_sha3_512(input_string: str) -> str:
    sha3_512_hash = sha3_512()
    sha3_512_hash.update(input_string.encode('utf-8'))
    return sha3_512_hash.hexdigest()
        
def encrypt(aesKey, iv, hashKey, file, textbox):
    text = textbox.get("1.0", tk.END)
    if len(aesKey) != 32 or not iv or not hashKey or not file or not text or not os.path.isfile(file):
        messagebox.showerror("Error", "AES-256 key must be 32 characters long. IV (CBC) must be 16 characters long. hash Key and textbox cannot be empty. File must exists.")
    else:
        mic = calculate_sha3_512(text + hashKey)
        textbox.delete(0, 'end')
        textbox.insert(0, "Encrypting...")
        chipertext = encrypt_AES256(aesKey.encode(), iv.encode(), mic + text)
        try:
            with open(file, 'wb', encoding='utf-8') as f:
                f.write(chipertext)
            textbox.delete(0, 'end')
            textbox.insert(0, f"Content encrypted in {file}.")
        except:
            textbox.delete(0, 'end')
            messagebox.showerror("Error", f"An error occured writing the chipertext in {file}")

def decrypt(aesKey, iv, hashKey, file, textbox):
    text = textbox.get("1.0", tk.END)
    if len(aesKey) != 32 or not iv or not hashKey or not file or not text or not os.path.isfile(file):
        messagebox.showerror("Error", "AES-256 key must be 32 characters long. IV (CBC) must be 16 characters long. hash Key and textbox cannot be empty. File must exists.")
    else:
        textbox.delete(0, 'end')
        textbox.insert(0, "Decrypting...")
        try:
            with open(file, 'rb', encoding='utf-8') as f:
                chipertext = f.read()
            ####
        except:
            textbox.delete(0, 'end')
            messagebox.showerror("Error", f"An error occured reading the chipertext in {file}")

def select_file(entry):
    selected_file = filedialog.askopenfilename()
    if selected_file:
        entry.delete(0, 'end')
        entry.insert(0, selected_file)

def secNotes_gui():
    root = tk.Tk()
    root.title("secNotes by Mqtth3w")
    root.resizable(False, False)
    
    tk.Label(root, text="Symmetric key AES-256 (32 characters):").grid(row=0, column=0)
    aesKey_entry = tk.Entry(root, width=50)
    aesKey_entry.grid(row=0, column=1)
    
    tk.Label(root, text="IV CBC mode (16 characters):").grid(row=1, column=0)
    iv_entry = tk.Entry(root, width=50)
    iv_entry.grid(row=1, column=1)
    
    tk.Label(root, text="Checksum key (at least one character):").grid(row=2, column=0)
    hashKey_entry = tk.Entry(root, width=50)
    hashKey_entry.grid(row=2, column=1)
    
    tk.Label(root, text="Path to the file (ex: the/file/name.txt):").grid(row=3, column=0)
    file_entry = tk.Entry(root, width=50)
    file_entry.grid(row=3, column=1)
    tk.Button(root, text="Browse", command=lambda: select_file(file_entry)).grid(row=3, column=2)

    tk.Label(root, text="The content of the following textbox will be encrypted in the specified \n"
                    "file with the given keys. To decrypt the specified file, you need \n"
                    "to use the same encryption keys. Please wait. \n").grid(row=5, columnspan=3)

    tk.Button(root, text="Encrypt", command=lambda: encrypt(aesKey_entry.get(),
        iv_entry.get(), hashKey_entry.get(), file_entry.get(), textbox
        )).grid(row=6, column=0)
    
    tk.Button(root, text="Decrypt and check integrity", command=lambda: decrypt(aesKey_entry.get(),
        iv_entry.get(), hashKey_entry.get(), file_entry.get(), textbox
        )).grid(row=6, column=1)
    
    textbox = tk.Text(root, width=100, height=30)
    textbox.grid(row=7, column=0, columnspan=3)

    root.mainloop()


if __name__ == "__main__":
    secNotes_gui()
