import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import json
import customtkinter as ctk
from tkinter import messagebox, filedialog


# Cryptographic Functions
def generate_hmac(data, key):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def encrypt_message(message, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    hmac_value = generate_hmac(ciphertext, key)
    return iv, ciphertext, hmac_value


def decrypt_message(iv, ciphertext, hmac_value, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    computed_hmac = generate_hmac(ciphertext, key)
    if computed_hmac != hmac_value:
        raise ValueError("HMAC verification failed. The message may be tampered.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode('utf-8')


def save_encrypted_message(iv, ciphertext, hmac_value, filename):
    data = {
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex(),
        'hmac': hmac_value,
    }
    with open(filename, 'w') as f:
        json.dump(data, f)


def load_encrypted_message(filename):
    with open(filename, 'r') as f:
        return json.load(f)


# GUI Application
class EncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Settings
        self.title("Encryption Utility")
        self.geometry("500x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Variables to Store Encrypted Data
        self.last_iv = None
        self.last_ciphertext = None
        self.last_hmac = None

        # Header Section
        self.header = ctk.CTkLabel(
            self, text="Encryption Utility", font=ctk.CTkFont(size=24, weight="bold")
        )
        self.header.pack(pady=20)

        # Input Section
        self.input_frame = ctk.CTkFrame(self, corner_radius=10)
        self.input_frame.pack(pady=10, padx=20, fill="x")

        self.message_label = ctk.CTkLabel(self.input_frame, text="Message:")
        self.message_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.message_entry = ctk.CTkEntry(self.input_frame, width=250)
        self.message_entry.grid(row=0, column=1, padx=10, pady=10)

        self.key_label = ctk.CTkLabel(
            self.input_frame, text="Key (16/24/32 characters):"
        )
        self.key_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.key_entry = ctk.CTkEntry(self.input_frame, width=250, show="*")
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)

        # Buttons Section
        self.buttons_frame = ctk.CTkFrame(self, corner_radius=10)
        self.buttons_frame.pack(pady=20, padx=20, fill="x")

        # Button Grid Layout
        self.encrypt_button = ctk.CTkButton(
            self.buttons_frame, text="Encrypt", command=self.encrypt_message, width=200
        )
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=10)

        self.decrypt_button = ctk.CTkButton(
            self.buttons_frame, text="Decrypt from JSON File", command=self.decrypt_from_file, width=200
        )
        self.decrypt_button.grid(row=0, column=1, padx=10, pady=10)

        self.hmac_button = ctk.CTkButton(
            self.buttons_frame, text="Generate HMAC", command=self.generate_hmac_ui, width=200
        )
        self.hmac_button.grid(row=1, column=0, padx=10, pady=10)

        self.save_button = ctk.CTkButton(
            self.buttons_frame, text="Save Encrypted Message", command=self.save_message, width=200
        )
        self.save_button.grid(row=1, column=1, padx=10, pady=10)

        self.clear_output_button = ctk.CTkButton(
            self.buttons_frame, text="Clear Output", command=self.clear_output, width=200
        )
        self.clear_output_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Output Section
        self.output_frame = ctk.CTkFrame(self, corner_radius=10)
        self.output_frame.pack(pady=10, padx=20, fill="x")

        self.output_label = ctk.CTkLabel(
            self.output_frame, text="Output:", anchor="w", font=("Arial", 12)
        )
        self.output_label.pack(pady=5, padx=10, anchor="w")

        self.output_text = ctk.CTkTextbox(self.output_frame, height=150, wrap="word")
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

    def display_output(self, message):
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", message)

    def clear_output(self):
        self.output_text.delete("1.0", "end")

    def encrypt_message(self):
        message = self.message_entry.get()
        key = self.key_entry.get()
        if not message or not key:
            messagebox.showerror("Error", "Message and key cannot be empty.")
            return
        try:
            iv, ciphertext, hmac_value = encrypt_message(message, key)
            self.last_iv = iv
            self.last_ciphertext = ciphertext
            self.last_hmac = hmac_value
            result = (
                f"IV: {iv.hex()}\n"
                f"Ciphertext: {ciphertext.hex()}\n"
                f"HMAC: {hmac_value}"
            )
            self.display_output(result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_message(self):
        if not self.last_iv or not self.last_ciphertext or not self.last_hmac:
            messagebox.showerror("Error", "No encrypted data available to save.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON files", "*.json")]
        )
        if not filename:
            return
        try:
            save_encrypted_message(self.last_iv, self.last_ciphertext, self.last_hmac, filename)
            messagebox.showinfo("Success", "Encrypted message saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_from_file(self):
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not filename:
            return
        try:
            key = self.key_entry.get()
            if not key:
                raise ValueError("Key cannot be empty.")
            data = load_encrypted_message(filename)
            iv = bytes.fromhex(data['iv'])
            ciphertext = bytes.fromhex(data['ciphertext'])
            hmac_value = data['hmac']
            decrypted_message = decrypt_message(iv, ciphertext, hmac_value, key)
            self.display_output(f"Decrypted Message:\n{decrypted_message}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_hmac_ui(self):
        message = self.message_entry.get()
        key = self.key_entry.get()
        if not message or not key:
            messagebox.showerror("Error", "Message and key cannot be empty.")
            return
        hmac_value = generate_hmac(message.encode(), key)
        self.display_output(f"HMAC: {hmac_value}")


if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
