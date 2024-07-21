#!py_virtual_env/bin/python3


import os
import secrets


def generate_and_write_secret(directory, file_name):
    random_binary = secrets.token_bytes(32)
    hex_representation = random_binary.hex()
    file_path = os.path.join(directory, file_name)
    with open(file_path, "w") as file:
        file.write(hex_representation)
    
    return file_path

if __name__ == "__main__":
    directory = "./crypto_data"
    file_name = "link_secret.txt"
    file_path = generate_and_write_secret(directory, file_name)
    print(f"Saved LinkSecretFile to {file_path}")
