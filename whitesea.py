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

def send_file_to_api(file_data):
        files = {
           "file": ("encrypted_model.bin", file_data, "application/octet-stream")
            }
        response = requests.post("https://e843-103-90-97-197.ngrok-free.app/upload_file_form_data"  , files=files)  # Use POST for file upload
        if response.status_code == 200:
         st.success("File sent successfully!")
        else:
         st.error(f"Error sending file: {response.text}")
         
def send_variable_to_api(api_url, variable_data):
    """
    Sends a variable to an API endpoint using POST request.

    Args:
        api_url (str): The URL of the API endpoint.
        variable_data (any): The variable data to be sent.

    Returns:
        requests.Response: The HTTP response object from the API request.
    """

    try:
        response = requests.post(
            api_url,
            json=variable_data  # Send the variable as JSON data
        )
    except requests.exceptions.RequestException as e:
        print(f"Error sending variable: {e}")
        return None  # Or handle the error in a more appropriate way

    return response

def send_file_to_api(api_url, key, file_data):
    """
    Sends a file to a FastAPI endpoint using form data.

    Args:
        api_url (str): The URL of the FastAPI endpoint.
        key (str): The key value to send with the request.
        file_data (bytes): The file data to upload.

    Returns:
        requests.Response: The response object from the API.
    """

    try:
        files = {"file": ("uploaded_file", file_data)}
        data = {"key": key}
        response = requests.post(api_url, files=files, data=data)
        response.raise_for_status()  # Raise an exception for non-200 status codes
        return response

    except requests.exceptions.RequestException as e:
        print(f"Error sending file: {e}")

    return None

         
# Streamlit App for Encryption
def main():
    st.title("Model Encryption App")
    st.header("Encrypt .h5 Model")

    model_file = st.file_uploader("Upload H5 Model", type=["h5"], key="encrypt")
    password = st.text_input("Set a password for encryption", type="password", key="password_enc")

    if model_file is not None and password:
        model_data = model_file.read()
        encrypted_model = encrypt_model(model_data, password)

        # Save the password to a text file automatically (optional)
        # ...

        # Send encrypted model to endpoint
        send_file_to_api(api_url="https://e843-103-90-97-197.ngrok-free.app/upload_file_from_data", key=password, file_data=encrypted_model)  # Call the function to upload
        response = send_variable_to_api("https://e843-103-90-97-197.ngrok-free.app/push_data",{'key' : password})
        if response.status_code == 200:
            print("succes key deplyed")
            
        else:
            print("error deply key")

if __name__ == '__main__':
    main()