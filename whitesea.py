import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
import requests

# Define key generation function
def generate_key(password: str, salt: bytes) -> bytes:
    """Generate AES key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encryption function
def encrypt_model(model_data: bytes, password: str) -> bytes:
    """Encrypt the model using AES."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(model_data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    encrypted_model = base64.b64encode(salt + iv + encrypted_data)
    
    return encrypted_model

# Streamlit App for Encryption
def main():
    st.title("Model Encryption App")
    
    st.header("Encrypt .h5 Model")
    
    model_file = st.file_uploader("Upload H5 Model", type=["h5"], key="encrypt")
    
    password = st.text_input("Set a password for encryption", type="password", key="password_enc")

    if model_file is not None and password:
        model_data = model_file.read()
        
        encrypted_model = encrypt_model(model_data, password)

        response = requests.post("https://273c-182-71-130-10.ngrok-free.app/upload", data=encrypted_model)
        print(response)
        # Save the password to a text file automatically
        with open("passwords.txt", "a") as f:
            f.write(password + "\n")  # Append password to the file

        st.download_button(
            label="Download Encrypted Model",
            data=encrypted_model,
            file_name="encrypted_model.bin",
            mime="application/octet-stream"
        )
        
        st.success("Password saved successfully.")

if __name__ == '__main__':
    main()
