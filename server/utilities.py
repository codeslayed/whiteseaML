import base64
import os
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import h5py
from io import BytesIO

import requests

# Replace with your endpoint URLs
upload_url = "https://d501-103-90-97-197.ngrok-free.app/upload/{bytes}"
download_url = "https://d501-103-90-97-197.ngrok-free.app/download"

with open("sampletext.txt", "rb") as file:
    files = {"file": file}
    response = requests.post(upload_url, files=files)
    print(response.json())

# Download the latest uploaded file
response = requests.get(download_url)
with open("downloaded_file.txt", "wb") as file:
    file.write(response.content)
