import os
from cryptography.fernet import Fernet


def get_key():
    key = os.environ.get("FERNET_KEY")

    if not key:
        raise RuntimeError("FERNET_KEY environment variable is not set.")

    return key.encode()


def encrypt_file(input_file, output_file):

    key = get_key()
    cipher = Fernet(key)

    with open(input_file, "rb") as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    with open(output_file, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(input_file, output_file):

    key = get_key()
    cipher = Fernet(key)

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    data = cipher.decrypt(encrypted_data)

    with open(output_file, "wb") as file:
        file.write(data)