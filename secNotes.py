'''
    @author Mqtth3w https://github.com/mqtth3w
    @license GPL-3.0
'''

from Crypto.Cipher import AES
from hashlib import sha3_512
import os
import tkinter as tk
from tkinter import filedialog, messagebox

key_len = 32
iv_len = 16
mic_len = 128

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
        
def encrypt(aesKey_entry, iv_entry, hashKey_entry, file, textbox, checklab):
    aesKey = bytearray(aesKey_entry.get(), 'utf-8')
    aesKey_entry.delete(0, tk.END)
    iv = bytearray(iv_entry.get(), 'utf-8')
    iv_entry.delete(0, tk.END)
    hashKey = bytearray(hashKey_entry.get(), 'utf-8')
    hashKey_entry.delete(0, tk.END)
    text = textbox.get(1.0, tk.END)
    if len(aesKey) != key_len:
        messagebox.showerror("Error", "AES-256 key must be 32 characters long.")
    elif len(iv) != iv_len:
        messagebox.showerror("Error", "IV (CBC) must be 16 characters long.")
    elif not hashKey:
        messagebox.showerror("Error", "Checksum key textbox cannot be empty.")
    elif not text.strip():
        messagebox.showerror("Error", "Text textbox cannot be empty.")
    elif not file:
        messagebox.showerror("Error", "File textbox cannot be empty.")
    elif not os.path.isfile(file):
        messagebox.showerror("Error", "File must exists.")
    else:
        checklab.config(text="")
        mic = calculate_sha3_512(text + hashKey.decode('utf-8'))
        hashKey[:] = b'\x00' * len(hashKey)
        textbox.delete(1.0, tk.END)
        textbox.insert(1.0, "Encrypting...")
        chipertext = encrypt_AES256(aesKey, iv, mic + text)
        aesKey[:] = b'\x00' * key_len
        iv[:] = b'\x00' * iv_len
        try:
            with open(file, 'wb') as f:
                f.write(chipertext)
            textbox.delete(1.0, tk.END)
            textbox.insert(1.0, f"Content encrypted in {file}.")
        except Exception as e:
            textbox.delete(1.0, tk.END)
            messagebox.showerror("Error", f"An error occured writing the chipertext in {file}: {e}")

def decrypt(aesKey_entry, iv_entry, hashKey_entry, file, textbox, checklab):
    aesKey = bytearray(aesKey_entry.get(), 'utf-8')
    aesKey_entry.delete(0, tk.END)
    iv = bytearray(iv_entry.get(), 'utf-8')
    iv_entry.delete(0, tk.END)
    hashKey = bytearray(hashKey_entry.get(), 'utf-8')
    hashKey_entry.delete(0, tk.END)
    if len(aesKey) != key_len:
        messagebox.showerror("Error", "AES-256 key must be 32 characters long.")
    elif len(iv) != iv_len:
        messagebox.showerror("Error", "IV (CBC) must be 16 characters long.")
    elif not hashKey:
        messagebox.showerror("Error", "Checksum key textbox cannot be empty.")
    elif not file:
        messagebox.showerror("Error", "File textbox cannot be empty.")
    elif not os.path.isfile(file):
        messagebox.showerror("Error", "File must exists.")
    else:
        textbox.delete(1.0, tk.END)
        textbox.insert(1.0, "Decrypting...")
        try:
            with open(file, 'rb') as f:
                chipertext = f.read()
            plaintext = decrypt_AES256(aesKey, iv, chipertext)
            aesKey[:] = b'\x00' * key_len
            iv[:] = b'\x00' * iv_len
            mic = plaintext[:mic_len]
            text = plaintext[mic_len:]
            valid = mic == calculate_sha3_512(text + hashKey.decode('utf-8'))
            hashKey[:] = b'\x00' * len(hashKey)
            checklab.config(text=f"Integrity check passed: {valid}")
            textbox.delete(1.0, tk.END)
            textbox.insert(tk.END, text)            
        except Exception as e:
            textbox.delete(1.0, tk.END)
            messagebox.showerror("Error", f"An error occured reading the chipertext in {file}: {e}")

def select_file(entry):
    selected_file = filedialog.askopenfilename()
    if selected_file:
        entry.delete(0, 'end')
        entry.insert(0, selected_file)

def update_length_label(entry, label):
    length = len(entry.get())
    label.config(text=f"Length: {length}")

def secNotes_gui():
    root = tk.Tk()
    root.title("secNotes by Mqtth3w")
    root.resizable(False, False)
    
    tk.Label(root, text="Symmetric key AES-256 (32 characters):").grid(row=0, column=0)
    aesKey_entry = tk.Entry(root, width=50, show='*')
    aesKey_entry.grid(row=0, column=1)
    aesKey_length_label = tk.Label(root, text="Length: 0")
    aesKey_length_label.grid(row=0, column=2)
    aesKey_entry.bind('<KeyRelease>', lambda event: update_length_label(aesKey_entry, aesKey_length_label))
    
    tk.Label(root, text="IV (CBC mode, 16 characters):").grid(row=1, column=0)
    iv_entry = tk.Entry(root, width=50, show='*')
    iv_entry.grid(row=1, column=1)
    iv_length_label = tk.Label(root, text="Length: 0")
    iv_length_label.grid(row=1, column=2)
    iv_entry.bind('<KeyRelease>', lambda event: update_length_label(iv_entry, iv_length_label))
    
    tk.Label(root, text="Key for the checksum (at least one character):").grid(row=2, column=0)
    hashKey_entry = tk.Entry(root, width=50, show='*')
    hashKey_entry.grid(row=2, column=1)
    hashKey_length_label = tk.Label(root, text="Length: 0")
    hashKey_length_label.grid(row=2, column=2)
    hashKey_entry.bind('<KeyRelease>', lambda event: update_length_label(hashKey_entry, hashKey_length_label))
    
    tk.Label(root, text="Path to the file ex: the/file/name.txt \n(in windows the file should be in the same position of the script):").grid(row=3, column=0)
    file_entry = tk.Entry(root, width=50)
    file_entry.grid(row=3, column=1)
    tk.Button(root, text="Browse", command=lambda: select_file(file_entry)).grid(row=3, column=2)

    tk.Label(root, text="Encypt: The contents of the following textbox will be encrypted in the specified file with the given keys.\n"
            "To decrypt the specified file, you need to use the same encryption keys.\n"
            "Decrypt: The contents of the encrypted file will be shown in the following textbox. Please wait.\n").grid(row=5, columnspan=3)

    tk.Button(root, text="Encrypt", command=lambda: encrypt(aesKey_entry,
        iv_entry, hashKey_entry, file_entry.get(), textbox, checklab
        )).grid(row=6, column=0)
    
    tk.Button(root, text="Decrypt and check integrity", command=lambda: decrypt(aesKey_entry,
        iv_entry, hashKey_entry, file_entry.get(), textbox, checklab
        )).grid(row=6, column=1)
    
    checklab = tk.Label(root, text="")
    checklab.grid(row=7, column=0)
    
    textbox = tk.Text(root, width=100, height=30)
    textbox.grid(row=8, column=0, columnspan=3)

    root.mainloop()


if __name__ == "__main__":
    secNotes_gui()
