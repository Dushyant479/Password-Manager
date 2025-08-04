import os
from encryption import encrypt_data, decrypt_data

VAULT_FILE = "data/vault.enc"

def save_vault(data: str, key: bytes):
    encrypted = encrypt_data(data, key)
    os.makedirs("data", exist_ok=True)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def load_vault(key: bytes) -> str:
    if not os.path.exists(VAULT_FILE):
        return ""
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    return decrypt_data(encrypted, key)
