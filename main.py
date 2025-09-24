import argparse
from cryptography.fernet import Fernet, InvalidToken
import os



"""
How to use:

1. Generate a new key:
   python (name_here).py generate "mykey.key"

2. Check if a key file is valid:
   python (name_here).py check "mykey.key"

3. Encrypt a file:
   python (name_here).py encrypt "mykey.key" "plain.txt" "encrypted.bin"

4. Decrypt a file:
   python (name_here).py decrypt "mykey.key" "encrypted.bin" "decrypted.txt"
 
"""


# Generate a key and save it
def generate(key_path):
    # Generate a new key using fernet
    # Fernet.generate_key() returns a key
    key = Fernet.generate_key()
    # Write they key to the specified file in binary mode
    with open(key_path, 'wb') as key_file: # Opens the file in write binary mode
        key_file.write(key) # writes the key
    print(f"Key successfully generated and saved to {key_path}")


def check_key(key_path):
    """
    Validate a key.

    You can make sure the file exists and contains a properlly formatted Fernet key.
    It's useful before encrypting or decrypting to prevent mistakes

    How it works:

    If the file doesn't exist, return False.
    It reads bytes and tries the Fernet key. If it constructs successfully, the key is valid
    """
    # Check if key file exists before attempting to read it
    if not os.path.exists(key_path):
        print(f"Key file {key_path} does not exist.")
        return
    try:
        # Read key bytes from disk
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
        # Creating a fernet object will validate the key format
        Fernet(key)
        print("Key is valid!")
        return True
    except Exception as e:
        # Check if format is invalid or other errors.
        print(f"Key is invalid: {e}")
        return False

# Encrypt a file using a Fernet key 
def encrypt_file(key_path, input_file, output_file):
    """
    How it works:
    It loads the key, creates a Fernet encryptor and reads the input file, then calls encrypt() and writes the encrypted data to output_file

    """
    try:
        # Read the key from key file
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        # Build a Fernet instance for encry 
        f = Fernet(key)
        # Read the data to encrypt from input file
        with open(input_file, "rb") as f_in:
            data = f_in.read()
        # Encrypt the data
        encrypted = f.encrypt(data)
        # Write encrypted data to output file
        with open(output_file, "wb") as f_out:
            f_out.write(encrypted)
        print(f"File {input_file} encrypted and saved to {output_file}")
    # Handle errors:
    except FileNotFoundError as fnf_error:
        print(f"[ERROR] File not found: {fnf_error}") # If there's no file to be found.
    except PermissionError as perm_error:
        print(f"[ERROR] Permssion denied: {perm_error}") # If there's no permission to read or write the files.
    except Exception as e: # Used for other issues
        print(f"Encryption failed: {e}") 

def decrypt_file(key_path, input_file, output_file):
    """
    How it works:
    
    It loads the key, creates a Fernet decryptor, reads the encrypted bytes and calls decrypt()
    Writes the recovered data to output_file

    If the key is invalid, Fernet.decrypt raises InvalidToken

    
    """
    
    # Read the key from the key file
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    # Again, create a Fernet instance for decryption
    f = Fernet(key)
    # Read the encrypted data from input_file in read binary mode
    with open(input_file, "rb") as f_in:
        encrypted_data = f_in.read()
    try:
        # Attempt to decrypt the data. If they key is wrong, raise InvalidToken
        decrypted = f.decrypt(encrypted_data)

        # Write the decrypted data to the output_file
        with open(output_file, 'wb') as f_out:
            f_out.write(decrypted)
        print(f"File {input_file} decrypted and saved to {output_file}")
    # Handle errors:
    except InvalidToken:
        # Wrong key or someone messed with the encrypted data
        print(f"[ERROR] Decryption failed due to an invalid key or corrupted file.")
    except Exception as e:
        # Other issues during decryption
        print(f"Decryption failed: {e}")


# Main function to set up CLI
def main():

    # Main parser
    # It shows description and help text
    parser = argparse.ArgumentParser(description="CLI File Encryptor")
    
    # Organize actios
    # required=True is used to make sure the user must use one subcommand
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")
    
     # Generate key command
    parser_gen = subparsers.add_parser("generate", help="Generate a new encryption key")
    parser_gen.add_argument("key_path", help="Path to save the generated key")

    # Check key command
    parser_check = subparsers.add_parser("check", help="Check if the key file is valid")
    parser_check.add_argument("key_path", help="Path to the key file")

    # Encrypt command
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a file")
    parser_encrypt.add_argument("key_path", help="Path to the key file")
    parser_encrypt.add_argument("input_file", help="Path to the file to encrypt")
    parser_encrypt.add_argument("output_file", help="Path to save the encrypted file")

    # Decrypt command
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a file")
    parser_decrypt.add_argument("key_path", help="Path to the key file")
    parser_decrypt.add_argument("input_file", help="Path to the encrypted file")
    parser_decrypt.add_argument("output_file", help="Path to save the decrypted file")

    # Parse CLI input
    args = parser.parse_args()

    # Call the right function based on the command the user used
    if args.command == "generate":
        generate(args.key_path)
    elif args.command == "check":
        check_key(args.key_path)
    elif args.command == "encrypt":
        encrypt_file(args.key_path, args.input_file, args.output_file)
    elif args.command == "decrypt":
        decrypt_file(args.key_path, args.input_file, args.output_file)
    else:
        # If user types an invalid command, it prints the help text.
        parser.print_help()

# Makes sure only main() runs duhh
if __name__ == "__main__":
    main()


