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


def send_get_request_with_path_parameter(api_url, path_parameter):
    """
    Sends a GET request to an API endpoint with a path parameter.

    Args:
        api_url (str): The URL of the API endpoint with a placeholder for the path parameter.
        path_parameter (any): The value to be used as the path parameter.

    Returns:
        requests.Response: The HTTP response object from the API request.
    """

    try:
        response = requests.get(api_url + path_parameter)
    except requests.exceptions.RequestException as e:
        print(f"Error sending GET request: {e}")
        return None  # Or handle the error in a more appropriate way

    return response

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
    
    
import os

def write_response_content_to_bin(response_content, file_path = "encOld.bin"):
    """
    Writes the content of a response object to a .bin file.

    Args:
        response_content (bytes): The content of the response object.
        file_path (str): The path where the .bin file should be saved.
    """

    try:
        with open(file_path, "wb") as file:
            file.write(response_content)
        print(f"File saved successfully: {file_path}")
    except Exception as e:
        print(f"Error writing file: {e}")

# Streamlit App for Decryption
def main():
    st.title("Model Decryption App")
    
    st.header("Decrypt .bin Model")
    
    # Upload the encrypted .bin file
    #encrypted_file = st.file_uploader("Upload Encrypted Model (.bin)", type=["bin"], key="decrypt")

    # Input for the decryption password
    decrypt_password = st.text_input("Enter password for decryption", type="password", key="password_dec")

    if decrypt_password:
        try:
            # Read the encrypted model data
            encrypted_model_data = send_get_request_with_path_parameter(api_url="https://e843-103-90-97-197.ngrok-free.app/get_data/",path_parameter=decrypt_password)
            print("")
            # Decrypt the model
        
            decrypted_model = decrypt_model(encrypted_model_data.content, decrypt_password)
            print("line 93")
            # Convert decrypted data to downloadable H5 file
            st.download_button(
                label="Download Decrypted Model",
                data=decrypted_model,
                file_name="decrypted_model.h5",
                mime="application/octet-stream"
            )
            print("line 101")
            st.success("Model decrypted successfully.")

        except Exception as e:
            st.error(f"Decryption failed: {e}")

if __name__ == '__main__':
    main()