"""This simple tool is generally used to hash (sha256, md5, base64) a password and crack a hashed password"""

import hashlib  # for md5 and sha-256
import base64  # for base-64
import sys  # for exit function


# ====================  Encryption Function  ==========================
def hash_passwd(algorithm, passwd):
    """Hashes the given plaintext with the selected algorithm."""
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    hasher.update(passwd.encode('utf-8'))
    return hasher.hexdigest()


# ====================  Decryption Function  ==========================
def crack_hash(algorithm, target_hash, wordlist_path):
    """Attempts to crack the hash using a wordlist."""
    try:
        with open(wordlist_path, "r") as wordlist:
            for line in wordlist:
                word = line.strip()
                if hash_passwd(algorithm, word) == target_hash:
                    return word
    except FileNotFoundError:
        print(f"Error: Wordlist file not found: {wordlist_path}")
    return None


# =======================================================================
"""Presents the main menu to the user and manages user interaction"""
print("\n========== H-Tool ==========\n")
while True:
    print("1. Encryption")
    print("2. Decryption")
    print("3. Exit")

    try:
        choice = int(input("\nMake a choice: "))

        if choice == 1:
            algorithm = input("\nSelect algorithm (sha256, md5, base64): ").lower()
            passwd = input("\nEnter your password: ")

            if algorithm in ("md5", "sha256"):
                hashed = hash_passwd(algorithm, passwd)
                print(f"{algorithm.upper()} hash: {hashed}\n")
            elif algorithm == "base64":
                encoded = base64.b64encode(passwd.encode('ascii')).decode('ascii')
                print(f"BASE64 Hash: {encoded}")
            else:
                print("Invalid algorithm selection.")

        elif choice == 2:
            algorithm = input("Select algorithm (md5, sha256, base64): ").lower()
            hashed_input = input(f"Enter the {algorithm.upper()} hash: ")

            if algorithm in ("md5", "sha256"):
                #
                wordlist_path = input("Enter wordlist file path: ")
                password = crack_hash(algorithm, hashed_input, wordlist_path)
                if password:
                    print(f"\nPassword found: {password}")
                else:
                    print("Password not found in the wordlist.")
            elif algorithm == "base64":
                try:
                    decoded = base64.b64decode(hashed_input).decode('ascii')
                    print(f"\nDecoded password: {decoded}")
                except:
                    print("Invalid BASE64 input.")
            else:
                print("Invalid algorithm selection.")

        elif choice == 3:
            print("The program was terminated.")
            sys.exit()

        else:
            print("Invalid choice. Please try again.")

    except ValueError:
        print("Invalid input. Please enter a number.")