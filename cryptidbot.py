import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

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
    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Generate key from password and salt
    key = generate_key(password, salt)
    
    # Initialize Cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the model data to AES block size (128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(model_data) + padder.finalize()
    
    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt, IV, and encrypted data
    encrypted_model = base64.b64encode(salt + iv + encrypted_data)

    return encrypted_model

# Decryption function
def decrypt_model(encrypted_model: bytes, password: str) -> bytes:
    """Decrypt the AES-encrypted model."""
    try:
        encrypted_model = base64.b64decode(encrypted_model)
        
        # Extract salt, IV, and encrypted data
        salt = encrypted_model[:16]
        iv = encrypted_model[16:32]
        encrypted_data = encrypted_model[32:]
        
        # Generate key from password and salt
        key = generate_key(password, salt)
        
        # Initialize Cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        model_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return model_data
    
    except ValueError as e:
        raise ValueError("Decryption failed. Possible reasons: incorrect password or file corruption.") from e
    except Exception as e:
        raise Exception("An error occurred during decryption.") from e

# Streamlit App
def main():
    st.title("Advanced Model Security App")
    
    # Tabbed UI for Encryption and Decryption
    tabs = st.tabs(["Encrypt Model", "Decrypt Model"])
    
    # Encryption Tab
    with tabs[0]:
        st.header("Encrypt .h5 Model")
        
        # Upload the model file
        model_file = st.file_uploader("Upload H5 Model", type=["h5"], key="encrypt")
        
        # Input for the password
        password = st.text_input("Set a password for encryption", type="password", key="password_enc")
        
        if model_file is not None and password:
            # Read the uploaded model file
            model_data = model_file.read()
            
            # Encrypt the model
            encrypted_model = encrypt_model(model_data, password)
            
            # Convert encrypted data to downloadable binary file
            st.download_button(
                label="Download Encrypted Model",
                data=encrypted_model,
                file_name="encrypted_model.bin",
                mime="application/octet-stream"
            )

    # Decryption Tab
    with tabs[1]:
        st.header("Decrypt .bin Model")
        
        # Upload the encrypted .bin file
        encrypted_file = st.file_uploader("Upload Encrypted Model (.bin)", type=["bin"], key="decrypt")
        
        # Input for the decryption password
        decrypt_password = st.text_input("Enter password for decryption", type="password", key="password_dec")
        
        if encrypted_file is not None and decrypt_password:
            try:
                # Read the encrypted model data
                encrypted_model_data = encrypted_file.read()
                
                # Decrypt the model
                decrypted_model = decrypt_model(encrypted_model_data, decrypt_password)
                
                # Convert decrypted data to downloadable H5 file
                st.download_button(
                    label="Download Decrypted Model",
                    data=decrypted_model,
                    file_name="decrypted_model.h5",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Decryption failed: {e}")

if __name__ == '__main__':
    main()
