import hmac
import hashlib
import secrets
from pathlib import Path

CRED_FILE = Path("users.txt")


def make_salt():
       # 16 random bytes, unique per user
       return secrets.token_bytes(16)


def hash_password(password, salt):
       # Baseline on purpose: fast SHA-256, weak for passwords (fixed in hardening)
       return hashlib.sha256(salt + password.encode("utf-8")).digest()


def find_user(username):
       # Returns (salt, hash) as bytes, or None if the user does not exist
       if not CRED_FILE.exists():
           return None
       for line in CRED_FILE.read_text().splitlines():
           name, salt_hex, hash_hex = line.split(":")
           if name == username:
               return bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
       return None


def register(username, password):
       # False if the username is taken, True after saving
       if find_user(username) is not None:
           return False
       salt = make_salt()
       digest = hash_password(password, salt)
       with CRED_FILE.open("a") as f:
           f.write(f"{username}:{salt.hex()}:{digest.hex()}\n")
       return True

def verify_login(username, password):
       # True only if the user exists and the password matches
       record = find_user(username)
       if record is None:
           return False
       salt, stored = record
       return hmac.compare_digest(hash_password(password, salt), stored)
