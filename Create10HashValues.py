import hashlib
import os

# List of top 10 popular hashing algorithms and their corresponding functions in hashlib
hash_algorithms = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "SHA3-224": hashlib.sha3_224,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512
}

def calculate_hash(file_path, hash_function):
    """Calculates the hash of a file using the specified hash function."""
    hash_obj = hash_function()
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None

def hash_file_with_algorithms(file_path):
    """Calculates and prints the hash values of a file using the top 10 hashing algorithms."""
    # Expand the user path (e.g., ~/ to /home/username/)
    file_path = os.path.expanduser(file_path)

    if not os.path.isfile(file_path):
        print(f"The specified path is not a file: {file_path}")
        return
    
    print(f"Hash values for: {file_path}\n")
    for algo_name, hash_function in hash_algorithms.items():
        hash_value = calculate_hash(file_path, hash_function)
        if hash_value:
            print(f"{algo_name}: {hash_value}\n")

# Prompt the user for the file path
file_path = input("Enter the path of the file to hash: ")
hash_file_with_algorithms(file_path)
