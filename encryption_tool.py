from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog, messagebox
import os

KEY = get_random_bytes(32)  # AES-256 uses 32-byte key
BLOCK_SIZE = AES.block_size

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data))

    enc_file = file_path + ".enc"
    with open(enc_file, 'wb') as f:
        f.write(cipher.iv + ciphertext)

    messagebox.showinfo("Success", f"File encrypted:\n{enc_file}")

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext))

    dec_file = file_path.replace(".enc", "_decrypted")
    with open(dec_file, 'wb') as f:
        f.write(decrypted_data)

    messagebox.showinfo("Success", f"File decrypted:\n{dec_file}")

# GUI
def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt_file(file_path)

def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt_file(file_path)

root = tk.Tk()
root.title("AES-256 Encryption Tool")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

tk.Label(frame, text="🔐 AES-256 File Encryption/Decryption Tool", font=("Arial", 14)).pack(pady=10)

tk.Button(frame, text="Encrypt File", command=select_file_encrypt, width=20, bg="lightblue").pack(pady=5)
tk.Button(frame, text="Decrypt File", command=select_file_decrypt, width=20, bg="lightgreen").pack(pady=5)

root.mainloop()
