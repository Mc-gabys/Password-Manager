# 🛡️ Password Manager - Mc-security

A simple but secure **password manager** built with **Python** and **PyQt6**, featuring strong password hashing, two-factor authentication (2FA with TOTP), and encrypted storage of accounts.

---

## ✨ Features
- **Master password** protected vault  
- Passwords hashed with `PBKDF2-HMAC-SHA256` (500,000 iterations + random salt)  
- **Two-Factor Authentication (2FA)** (Google Authenticator, Microsoft Authenticator compatible)  
- Symmetric encryption with `Fernet (AES-128 in CBC + HMAC)`  
- Vault stored in an encrypted SQLite database  
- Integrity verification with HMAC (detects vault/key tampering)  
- Password strength meter using `zxcvbn`  
- Cross-platform GUI with PyQt6  

---

## 📦 Requirements
- Python **3.10+**

---

## 🛠️ How to use
- Download the repo:
  ```bash
  git clone https://github.com/Mc-gabys/Password-Manager
- Go to the directory:
  ```bash
  cd Password-Manager
- Install dependencies:
  ```bash
  python -m pip install -r requirements.txt
- Run the script:
  ```bash
  python3 main.py

---

## Support me on KoFi ❤️
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/N4N61K5R2A)

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
