import random
import string
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import os

# Dictionary to keep track of generated usernames
username_counts = {}

def generate_password(length=10):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

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

def save_credentials_to_file(encrypted_username, encrypted_password, key, file_path):
    try:
        with open(file_path, "ab") as file:  # Append to the file
            file.write(b"Key: " + key + b"\n")
            file.write(b"Encrypted Username: " + encrypted_username + b"\n")
            file.write(b"Encrypted Password: " + encrypted_password + b"\n")
        print(f"Credentials saved to: {file_path}")  # Add this line to print the file path
    except IOError as e:
        messagebox.showerror("Error", f"Failed to save credentials: {e}")

def generate_username(first_name, last_name):
    base_username = f"{first_name[0].lower()}{last_name.lower()}"
    if base_username in username_counts:
        username_counts[base_username] += 1
        return f"{base_username}{username_counts[base_username]}"
    else:
        username_counts[base_username] = 1
        return base_username

def generate_credentials():
    try:
        key = generate_key()
        password_length = int(password_length_entry.get())
        file_path = file_path_entry.get()
        first_name = first_name_entry.get()
        last_name = last_name_entry.get()
        
        # Validate input lengths
        if password_length < 8 or password_length > 128:
            raise ValueError("Password length must be between 8 and 128 characters.")
        
        # Validate first and last name
        if not first_name.isalpha() or not last_name.isalpha():
            raise ValueError("First and last name must contain only alphabetic characters.")
        
        password = generate_password(password_length)
        username = generate_username(first_name, last_name)
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
        
        # Save credentials to file
        save_credentials_to_file(encrypted_username, encrypted_password, key, file_path)
        
        # Clear sensitive data from memory
        del password
        del username
        del key
        del encrypted_password
        del encrypted_username
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def import_usernames():
    file_path = filedialog.askopenfilename(title="Select Usernames File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    if file_path:
        try:
            with open(file_path, "r") as file:
                lines = file.readlines()
                for line in lines:
                    first_name, last_name = line.strip().split()
                    generate_credentials_for_user(first_name, last_name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import usernames: {e}")

def generate_credentials_for_user(first_name, last_name):
    try:
        key = generate_key()
        password_length = int(password_length_entry.get())
        file_path = file_path_entry.get()
        
        # Validate input lengths
        if password_length < 8 or password_length > 128:
            raise ValueError("Password length must be between 8 and 128 characters.")
        
        password = generate_password(password_length)
        username = generate_username(first_name, last_name)
        encrypted_password = encrypt_data(password, key)
        encrypted_username = encrypt_data(username, key)
        
        # Save credentials to file
        save_credentials_to_file(encrypted_username, encrypted_password, key, file_path)
        
        # Clear sensitive data from memory
        del password
        del username
        del key
        del encrypted_password
        del encrypted_username
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the GUI
root = tk.Tk()
root.title("Password and Username Generator")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

tk.Label(frame, text="Password Length:").pack()
password_length_entry = tk.Entry(frame)
password_length_entry.pack()
password_length_entry.insert(0, "10")

tk.Label(frame, text="First Name:").pack()
first_name_entry = tk.Entry(frame)
first_name_entry.pack()

tk.Label(frame, text="Last Name:").pack()
last_name_entry = tk.Entry(frame)
last_name_entry.pack()

tk.Label(frame, text="File Path:").pack()
file_path_entry = tk.Entry(frame)
file_path_entry.pack()
file_path_entry.insert(0, "credentials.txt")

generate_button = tk.Button(frame, text="Generate Credentials", command=generate_credentials)
generate_button.pack(pady=10)

import_button = tk.Button(frame, text="Import Usernames", command=import_usernames)
import_button.pack(pady=10)

root.mainloop()