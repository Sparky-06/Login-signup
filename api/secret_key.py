from cryptography.fernet import Fernet
import os

DATA_FILE = 'secret.key'

def create_load_key():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'rb') as fp:
            return fp.read()
    else:
        key = Fernet.generate_key()
        with open(DATA_FILE, 'wb') as fp:
            fp.write(key)
        return key

