import socket
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# AES Key for AES-256 (32 bytes)
AES_KEY = b"this_is_a_32_byte_key_for_aes!!!"  # Ensure it's 32 bytes

# File for storing user credentials
DATA_FILE = "users.json"

# Encrypt password with AES-256
def encrypt_password(password):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return iv.hex(), encrypted_password.hex()

# Decrypt password with AES-256
def decrypt_password(iv_hex, encrypted_password_hex):
    iv = bytes.fromhex(iv_hex)
    encrypted_password = bytes.fromhex(encrypted_password_hex)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_password = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    password = unpadder.update(padded_password) + unpadder.finalize()
    return password.decode()

# Load users from the JSON file
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save users to the JSON file
def save_users(users):
    with open(DATA_FILE, "w") as f:
        json.dump(users, f)
    print("User data saved to users.json")  # Debugging statement

# Handle client requests
def handle_client(client_socket):
    users = load_users()
    data = client_socket.recv(1024).decode()
    request = json.loads(data)
    action = request["action"]
    username = request["username"]
    password = request["password"]

    if action == "signup":
        if username in users:
            response = "Username already exists."
            print(f"Sign-up failed: {username} already exists")  # Debugging statement
        else:
            iv, encrypted_password = encrypt_password(password)
            users[username] = {"iv": iv, "password": encrypted_password}
            save_users(users)
            response = "Sign-up successful."
            print(f"New user signed up: {username}")  # Debugging statement
    elif action == "login":
        if username not in users:
            response = "Username not found."
            print(f"Login failed: {username} not found")  # Debugging statement
        else:
            stored_iv = users[username]["iv"]
            stored_encrypted_password = users[username]["password"]
            stored_password = decrypt_password(stored_iv, stored_encrypted_password)
            if stored_password == password:
                response = "Login successful."
                print(f"User logged in: {username}")  # Debugging statement
            else:
                response = "Incorrect password."
                print(f"Login failed: incorrect password for {username}")  # Debugging statement

    client_socket.send(response.encode())
    client_socket.close()

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 65432))
server_socket.listen(5)
print("Server is listening...")

while True:
    client_socket, addr = server_socket.accept()
    handle_client(client_socket)
