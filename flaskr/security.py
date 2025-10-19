import hashlib
import bcrypt
import os
import base64
import argon2
import time

from argon2 import PasswordHasher

# Argon2 instance with moderate cost
argon2_hasher = argon2.PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=2
)

"""
Hash a password with a selected algorithm.
Supported: sha256, sha3, bcrypt, argon2
"""
def hash_password(password: str, algo='argon2') -> str:
    password_bytes = password.encode("utf-8")

    if algo == "sha256":
        salt = os.urandom(16)
        hash_bytes = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 100_000)
        return f"sha256${base64.b64encode(salt).decode()}${base64.b64encode(hash_bytes).decode()}"

    elif algo == "sha3":
        salt = os.urandom(16)
        hash_bytes = hashlib.pbkdf2_hmac("sha3_256", password_bytes, salt, 100_000)
        return f"sha3${base64.b64encode(salt).decode()}${base64.b64encode(hash_bytes).decode()}"

    elif algo == "bcrypt":
        salt = bcrypt.gensalt(rounds=12)
        hash_bytes = bcrypt.hashpw(password_bytes, salt)
        return f"bcrypt${hash_bytes.decode()}"

    elif algo == "argon2":
        return f"argon2${argon2_hasher.hash(password)}"

    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

"""Verify password using same algorithm and salt."""
def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against its stored hash."""
    algo, rest = stored_hash.split("$", 1)
    password_bytes = password.encode("utf-8")

    if algo == "sha256" or algo == "sha3":
        salt, b64_hash = rest.split("$")
        salt_bytes = base64.b64decode(salt)
        stored_bytes = base64.b64decode(b64_hash)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256" if algo == "sha256" else "sha3_256",
            password_bytes,
            salt_bytes,
            100_000
        )
        return new_hash == stored_bytes

    elif algo == "bcrypt":
        return bcrypt.checkpw(password_bytes, rest.encode())

    elif algo == "argon2":
        try:
            argon2_hasher.verify(rest, password)
            return True
        except Exception:
            return False

    return False

def compare_algorithms(password="Password123!"):
    """Benchmark, compare hash formats, and verify correctness."""
    algos = ["sha256", "sha3", "bcrypt", "argon2"]

    print("=== Password Hashing Comparison ===\n")

    hashes = {}

    for algo in algos:
        start = time.perf_counter()
        hashed = hash_password(password, algo)
        elapsed = time.perf_counter() - start

        hashes[algo] = hashed  # store for later verification

        print(f"Algorithm: {algo}")
        print(f"Time taken: {elapsed:.3f}s")
        print(f"Hash format (truncated): {hashed[:100]}...")
        print("-" * 80)

    print("\nVerification Test:\n")
    for algo, hashed in hashes.items():
        if verify_password(password, hashed):
            print(f"✔ {algo} verified successfully.")
        else:
            print(f"✖ {algo} verification failed.")

if __name__ == "__main__":
    compare_algorithms()        
