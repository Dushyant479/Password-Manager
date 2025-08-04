import os
import bcrypt

HASH_FILE = "data/master.hash"

def is_first_run():
    return not os.path.exists(HASH_FILE)

def save_master_password(password: str):
    os.makedirs("data", exist_ok=True)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with open(HASH_FILE, "wb") as f:
        f.write(hashed)

def verify_master_password(password: str) -> bool:
    if not os.path.exists(HASH_FILE):
        return False
    with open(HASH_FILE, "rb") as f:
        stored_hash = f.read()
    return bcrypt.checkpw(password.encode(), stored_hash)
