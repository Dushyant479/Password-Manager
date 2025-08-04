# Password Manager

A secure and user-friendly desktop password manager built with Python. It allows you to store, generate, and manage your passwords safely with encryption and a master password for access. The application features a clean graphical interface using Tkinter.

---

## Features

- Protect your passwords with a **master password** hashed securely using bcrypt.
- Store all password entries in an encrypted vault using **modern encryption (Fernet with PBKDF2-based keys)**.
- **Add, edit, delete, and view password entries** with ease.
- **Generate strong passwords** with customizable length.
- Copy passwords to clipboard securely, with automatic clearing after 15 seconds.
- Responsive and intuitive **Tkinter GUI** for smooth user experience.
- Password vault stored locally in encrypted form.

---

## Requirements

- Python 3.7 or higher
- `cryptography` library
- `bcrypt` library
- `pyperclip` library (for clipboard handling)
- `tkinter` (usually included with Python)

Install required packages using pip:

pip install cryptography bcrypt pyperclip

text

---

## Usage

1. Clone or download the repository:

git clone <your-repo-url>
cd <repo-folder>

text

2. Run the application:

python main.py

text

3. On the first run, you will be prompted to create and confirm a master password. On subsequent runs, enter the master password to unlock your vault.

4. Use the GUI to add, edit, or delete password entries. Each entry includes service name, username, and password.

5. Generate strong passwords as needed and copy passwords to clipboard securely.

6. Save your vault regularly to protect any changes.

---

## File Structure

| File            | Description                                      |
|-----------------|-------------------------------------------------|
| `main.py`       | Main application with full GUI and logic        |
| `auth.py`       | Master password hashing and verification using bcrypt |
| `encryption.py` | Encryption and decryption utilities using cryptography's Fernet |
| `vault.py`      | Saving and loading encrypted password vault data |
| `utils.py`      | Utility function to generate strong passwords    |

---

## Security Details

- Master password is securely hashed with bcrypt and stored locally.
- Vault data is encrypted with Fernet symmetric encryption using a key derived with PBKDF2HMAC and a random salt.
- Passwords are never stored or transmitted in plain text.
- Clipboard is cleared automatically after 15 seconds for security.
- Vault file is saved encrypted on disk (`data/vault.enc`).
- Salt is stored separately for key derivation (`data/salt.bin`).

---

## Acknowledgments

- [cryptography Python package](https://cryptography.io/)
- [bcrypt](https://pypi.org/project/bcrypt/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)

---

*For questions, issues, or contributions, please open an issue or a pull request on GitHub.*
