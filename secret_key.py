import os
from cryptography.fernet import Fernet

def create_load_key():
    key = os.environ.get("SECRET_KEY")
    if key is None:
        raise ValueError("SECRET_KEY environment variable not set")
    return key.encode()
