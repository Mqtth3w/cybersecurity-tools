'''
    @author Mqtth3w https://github.com/mqtth3w
    @license GPL-3.0
'''

from Crypto.Cipher import AES
from hashlib import sha3_512
import ctypes
import os
import tkinter as tk
from tkinter import filedialog, messagebox

key_len = 32
iv_len = 16
mic_len = 64 #bytes

def pad(data: bytes, blockSize: int) -> bytes:
    padLen = blockSize - (len(data) % blockSize)
    return data + (bytes([padLen]) * padLen)

def unpad(data: bytes, blockSize: int) -> bytes:
    return data[:-ord(data[-1:])]

def encrypt_AES256(KEY: bytes, IV: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt_AES256(KEY: bytes, IV: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

def calculate_sha3_512(input_string: bytes) -> bytes:
    sha3_512_hash = sha3_512()
    sha3_512_hash.update(input_string) 
    return sha3_512_hash.digest() #64 bytes

def clear_data(data: bytearray):
    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data))
    data.clear()

def encrypt(pdir, cdir, aesKey_entry, iv_entry, hashKey_entry, textbox):
    aesKey_str = aesKey_entry.get()
    iv_str = iv_entry.get()
    hashKey = bytearray(hashKey_entry.get(), 'utf-8')
    if len(aesKey_str) != key_len:
        messagebox.showerror("Error", "AES-256 key must be 32 characters long.")
    elif not all(ord(c) < 128 for c in aesKey_str):
        messagebox.showerror("Error", "AES-256 key must contain only ASCII characters.")
    elif len(iv_str) != iv_len:
        messagebox.showerror("Error", "IV (CBC) must be 16 characters long.")
    elif not all(ord(c) < 128 for c in iv_str):
        messagebox.showerror("Error", "IV (CBC) must contain only ASCII characters.")
    elif not hashKey:
        messagebox.showerror("Error", "Checksum key textbox cannot be empty.")
    elif not pdir or not cdir:
        messagebox.showerror("Error", "Plain-directory and chiper-directory textboxes cannot be empty.")
    elif not os.path.isdir(pdir) or not os.path.isdir(cdir):
        messagebox.showerror("Error", "Plain-directory and chiper-directory must exist.")
    else:
        aesKey = bytearray(aesKey_str, 'utf-8')
        aesKey_entry.delete(0, tk.END)
        iv = bytearray(iv_str, 'utf-8')
        iv_entry.delete(0, tk.END)
        hashKey_entry.delete(0, tk.END)
        textbox.delete(1.0, tk.END)
        textbox.insert(1.0, "Processing images...\n")
        for filename in os.listdir(pdir):
            file_path = os.path.join(pdir, filename)
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                try:
                    with open(file_path, 'rb') as img_file:
                        plain_img = img_file.read()
                    mic = calculate_sha3_512(plain_img + hashKey)
                    chiper_img = encrypt_AES256(aesKey, iv, mic + plain_img)
                    output_file_path = cdir + f"/enc_{filename}"
                    with open(output_file_path, 'wb') as output_file:
                        output_file.write(chiper_img)
                    textbox.insert(tk.END, f"Encrypted {filename} and saved to {output_file_path}.\n\n")
                except Exception as e:
                    textbox.insert(tk.END, f"Error processing {filename}: {e}.\n\n")
        clear_data(aesKey)
        clear_data(iv)
        clear_data(hashKey)

def decrypt(pdir, cdir, aesKey_entry, iv_entry, hashKey_entry, textbox):
    aesKey_str = aesKey_entry.get()
    iv_str = iv_entry.get()
    hashKey = bytearray(hashKey_entry.get(), 'utf-8')
    if len(aesKey_str) != key_len:
        messagebox.showerror("Error", "AES-256 key must be 32 characters long.")
    elif not all(ord(c) < 128 for c in aesKey_str):
        messagebox.showerror("Error", "AES-256 key must contain only ASCII characters.")
    elif len(iv_str) != iv_len:
        messagebox.showerror("Error", "IV (CBC) must be 16 characters long.")
    elif not all(ord(c) < 128 for c in iv_str):
        messagebox.showerror("Error", "IV (CBC) must contain only ASCII characters.")
    elif not hashKey:
        messagebox.showerror("Error", "Checksum key textbox cannot be empty.")
    elif not pdir or not cdir:
        messagebox.showerror("Error", "Plain-directory and chiper-directory textboxes cannot be empty.")
    elif not os.path.isdir(pdir) or not os.path.isdir(cdir):
        messagebox.showerror("Error", "Plain-directory and chiper-directory must exist.")
    else:
        aesKey = bytearray(aesKey_str, 'utf-8')
        aesKey_entry.delete(0, tk.END)
        iv = bytearray(iv_str, 'utf-8')
        iv_entry.delete(0, tk.END)
        hashKey_entry.delete(0, tk.END)
        textbox.delete(1.0, tk.END)
        textbox.insert(1.0, "Processing images...\n\n")
        for filename in os.listdir(cdir):
            file_path = os.path.join(cdir, filename)
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                try:
                    with open(file_path, 'rb') as img_file:
                        chiper_img = img_file.read()
                    plain_img = decrypt_AES256(aesKey, iv, chiper_img)
                    mic = plain_img[:mic_len]
                    img_data = plain_img[mic_len:]
                    valid = mic == calculate_sha3_512(img_data + hashKey)
                    if filename.startswith("enc_"):
                        filename = filename[len("enc_"):]
                    output_file_path = pdir + f"plain_{filename}"
                    with open(output_file_path, 'wb') as output_file:
                        output_file.write(plain_img)
                    textbox.insert(tk.END, f"Decrypted {filename} and saved to {output_file_path}. Integrity check passed: {valid}.\n\n")
                except Exception as e:
                    textbox.insert(tk.END, f"Error processing {filename}: {e}.\n\n")
        clear_data(aesKey)
        clear_data(iv)
        clear_data(hashKey)

def select_directory(entry):
    selected_directory = filedialog.askdirectory()
    if selected_directory:
        entry.delete(0, 'end')
        entry.insert(0, selected_directory)

def update_length_label(entry, label):
    length = len(entry.get())
    label.config(text=f"Length: {length}")

def secImgs_gui():
    root = tk.Tk()
    root.title("secImgs by Mqtth3w")
    root.resizable(False, False)
    
    tk.Label(root, text="Symmetric key AES-256 (32 ASCII characters):").grid(row=0, column=0)
    aesKey_entry = tk.Entry(root, width=50, show='*')
    aesKey_entry.grid(row=0, column=1)
    aesKey_length_label = tk.Label(root, text="Length: 0")
    aesKey_length_label.grid(row=0, column=2)
    aesKey_entry.bind('<KeyRelease>', lambda event: update_length_label(aesKey_entry, aesKey_length_label))
    
    tk.Label(root, text="IV (CBC mode, 16 ASCII characters):").grid(row=1, column=0)
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
    
    tk.Label(root, text="Plain-directory: ./the/plain/dir/ \n(in windows data should be in the same position of the script):").grid(row=3, column=0)
    pdir_entry = tk.Entry(root, width=50)
    pdir_entry.grid(row=3, column=1)
    tk.Button(root, text="Browse", command=lambda: select_directory(pdir_entry)).grid(row=3, column=2)
    
    tk.Label(root, text="Chiper-directory: ./the/chiper/dir/ \n(in windows data should be in the same position of the script):").grid(row=4, column=0)
    cdir_entry = tk.Entry(root, width=50)
    cdir_entry.grid(row=4, column=1)
    tk.Button(root, text="Browse", command=lambda: select_directory(cdir_entry)).grid(row=4, column=2)
    
    tk.Label(root, text="Encypt: All the images in the palin-directory will be encrypted in the chiper-directory with the given keys.\n"
            "To decrypt, you need to use the same encryption keys.\n"
            "Decrypt: All the images in the chiper-directory will be decrypted in the plain-directory. Please wait.\n").grid(row=5, columnspan=3)

    tk.Button(root, text="Encrypt", command=lambda: encrypt(pdir_entry.get(), cdir_entry.get(),
        aesKey_entry, iv_entry, hashKey_entry, textbox)).grid(row=6, column=0)
    
    tk.Button(root, text="Decrypt and check integrity", command=lambda: decrypt(pdir_entry.get(),
        cdir_entry.get(), aesKey_entry, iv_entry, hashKey_entry, textbox)).grid(row=6, column=1)
    
    textbox = tk.Text(root, width=100, height=30)
    textbox.grid(row=7, column=0, columnspan=3)

    root.mainloop()


if __name__ == "__main__":
    secImgs_gui()
