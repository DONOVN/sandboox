import random
import string
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

def generate_password(length=10):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def generate_username(length=8):
    characters = string.ascii_letters + string.digits
    username = ''.join(random.choice(characters) for i in range(length))
    return username

def check_password_strength(password):
    criteria = {
        "length": len(password) >= 10,
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digit": any(char.isdigit() for char in password),
        "special": any(char in string.punctuation for char in password)
    }
    strength = sum(criteria.values())
    return strength

def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

def generate_credentials():
    key = generate_key()
    password = generate_password()
    username = generate_username()
    encrypted_password = encrypt_data(password, key)
    encrypted_username = encrypt_data(username, key)
    
    password_strength = check_password_strength(password)
    
    result = (
        f"Generated password and username.\n"
        f"Password strength: {password_strength}\n"
        f"Encrypted password and username stored securely.\n"
        f"Decrypted password and username for verification:\n"
        f"Decrypted password: {decrypt_data(encrypted_password, key)}\n"
        f"Decrypted username: {decrypt_data(encrypted_username, key)}"
    )
    
    messagebox.showinfo("Credentials", result)

# Create the GUI
root = tk.Tk()
root.title("Password and Username Generator")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

generate_button = tk.Button(frame, text="Generate Credentials", command=generate_credentials)
generate_button.pack(pady=10)

root.mainloop()