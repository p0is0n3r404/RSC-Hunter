import hashlib
import re

def identify_hash(hash_string):
    """
    Identifies common hash algorithms based on length and character set.
    """
    hash_string = hash_string.strip()
    length = len(hash_string)
    
    # Check if hex
    if not re.match(r'^[a-fA-F0-9]+$', hash_string):
        return "Unknown (Not a valid hex string)"

    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    elif length == 128:
        return "SHA-512"
    else:
        return f"Unknown (Length: {length})"

if __name__ == "__main__":
    # Test cases
    print(identify_hash("5d41402abc4b2a76b9719d911017c592")) # MD5
    print(identify_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")) # SHA-1
