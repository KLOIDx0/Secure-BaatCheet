from hashlib import sha256


def derive_key(shared):
    # Turn the big DH integer into a 32-byte AES-256 key
    length = (shared.bit_length() + 7) // 8
    return sha256(shared.to_bytes(length, "big")).digest()
