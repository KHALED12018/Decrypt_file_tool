import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES, DES, Blowfish, ARC4, DES3
from Crypto.PublicKey import RSA
import binascii
import zlib
from Crypto.Util.Padding import pad, unpad

def xor_decrypt(ciphertext, key):
    return bytes([c ^ key for c in ciphertext])

def identify_cipher_and_key_length(ciphertext_hex, endian='big'):
    try:
        ciphertext = binascii.unhexlify(ciphertext_hex)
    except binascii.Error as e:
        print(f"Error: {e}")
        return

    if endian == 'little':
        ciphertext = ciphertext[::-1]

    algorithms = [AES, DES, Blowfish, ARC4, DES3]
    identified_ciphers = []
    for algorithm in algorithms:
        for key_length in [16, 24, 32]:
            try:
                cipher = algorithm.new(ciphertext[:key_length], AES.MODE_ECB)
                decrypted = cipher.decrypt(ciphertext[key_length:])
                identified_ciphers.append((algorithm.__name__, key_length, ciphertext[:key_length], decrypted))
            except ValueError:
                pass

    try:
        key = RSA.import_key(ciphertext)
        identified_ciphers.append(('RSA', key.size_in_bits(), ciphertext, key.decrypt(ciphertext)))
    except (ValueError, IndexError):
        pass

    # XOR decryption attempt
    for xor_key in range(256):
        xor_decrypted = xor_decrypt(ciphertext, xor_key)
        identified_ciphers.append(('XOR', 'Unknown', bytes([xor_key]), xor_decrypted))

    return identified_ciphers

def check_encryption(ciphertext_hex):
    identified_ciphers = identify_cipher_and_key_length(ciphertext_hex)
    return bool(identified_ciphers)

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_label.config(text=file_path)
        with open(file_path, 'rb') as file:
            ciphertext_hex = file.read().hex()
        is_encrypted = check_encryption(ciphertext_hex)
        if is_encrypted:
            identified_ciphers = identify_cipher_and_key_length(ciphertext_hex)
            cipher_text.delete(1.0, tk.END)
            cipher_text.insert(tk.END, "{:<12} {:<12} {:<64} {:<10}\n".format(
                "Crypt Type", "Key Length", "CRC32", "Key"
            ))
            cipher_text.insert(tk.END, "-"*105 + "\n")
            for cipher in identified_ciphers:
                crc32_value = zlib.crc32(cipher[3])
                cipher_text.insert(tk.END, "{:<12} {:<12} {:<10} {:<64}\n".format(
                    cipher[0], cipher[1], crc32_value, cipher[2].hex()
                ))
                cipher_text.insert(tk.END, " " * 28 + f"{len(cipher[3])} bytes\n")
        else:
            cipher_text.delete(1.0, tk.END)
            cipher_text.insert(tk.END, "No encryption found in the file.")
    else:
        file_path_label.config(text="Select a file to decrypt:")

def decrypt_file():
    file_path = file_path_label.cget("text")
    if not file_path or file_path == "Select a file to decrypt:":
        result_label.config(text="Please select a file to decrypt.")
        return

    with open(file_path, 'rb') as file:
        ciphertext_hex = file.read().hex()
    is_encrypted = check_encryption(ciphertext_hex)
    if is_encrypted:
        identified_ciphers = identify_cipher_and_key_length(ciphertext_hex)
        with open('decrypted_file', 'wb') as f:
            for cipher in identified_ciphers:
                f.write(cipher[3])
        result_label.config(text="Decryption successful. Decrypted file saved as 'decrypted_file'.")
    else:
        result_label.config(text="No encryption found in the file.")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Dragon_Noir_Decrypt Tool 2023")
    root.geometry("800x400")

    header_frame = tk.Frame(root, bg="blue", height=50)
    header_frame.pack(fill=tk.X)

    content_frame = tk.Frame(root)
    content_frame.pack(padx=50, pady=20)

    header_label = tk.Label(header_frame, text="Dragon_Noir_Decrypt Tool 2023", font=("Arial", 16), fg="white", bg="blue")
    header_label.pack(expand=True, fill=tk.BOTH)

    file_path_label = tk.Label(content_frame, text="Select a file to decrypt:", font=("Arial", 12))
    file_path_label.pack()

    cipher_text = tk.Text(content_frame, font=("Arial", 10), height=10, width=100)
    cipher_text.pack()

    result_label = tk.Label(content_frame, text="", font=("Arial", 12), fg="red")
    result_label.pack()

    browse_button = tk.Button(content_frame, text="Browse", command=browse_file)
    browse_button.pack(pady=10)

    decrypt_button = tk.Button(content_frame, text="Decrypt", command=decrypt_file)
    decrypt_button.pack()

    root.mainloop()

