import hashlib
import os
import base64
import bcrypt
import argon2

# Argon2 password hasher
argon2_hasher = argon2.PasswordHasher()

def hash_password(password: str, algo='bcrypt'):
    """Hash password with a selected algorithm: sha256, sha3, bcrypt, argon2."""
    if algo == 'sha256':
        salt = os.urandom(16)
        h = hashlib.sha256(salt + password.encode()).digest()
        return base64.b64encode(salt).decode(), base64.b64encode(h).decode()
    elif algo == 'sha3':
        salt = os.urandom(16)
        h = hashlib.sha3_256(salt + password.encode()).digest()
        return base64.b64encode(salt).decode(), base64.b64encode(h).decode()
    elif algo == 'bcrypt':
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return None, hashed.decode()
    elif algo == 'argon2':
        hashed = argon2_hasher.hash(password)
        return None, hashed
    else:
        raise ValueError('Unsupported algorithm')

def verify_password(password: str, salt: str, stored_hash: str, algo='bcrypt'):
    """Verify password using same algorithm and salt."""
    if algo == 'sha256':
        salt_bytes = base64.b64decode(salt)
        h = hashlib.sha256(salt_bytes + password.encode()).digest()
        return base64.b64encode(h).decode() == stored_hash
    elif algo == 'sha3':
        salt_bytes = base64.b64decode(salt)
        h = hashlib.sha3_256(salt_bytes + password.encode()).digest()
        return base64.b64encode(h).decode() == stored_hash
    elif algo == 'bcrypt':
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    elif algo == 'argon2':
        try:
            argon2_hasher.verify(stored_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
