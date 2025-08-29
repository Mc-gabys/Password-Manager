import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QTreeWidget, QTreeWidgetItem, QFormLayout, QDialog, QDialogButtonBox, QComboBox, QProgressBar
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from cryptography.fernet import Fernet
import sys
import hashlib
import hmac
import sqlite3
import base64
import pyotp
import qrcode
from io import BytesIO
import zxcvbn

base_path = os.path.join(os.path.dirname(__file__), "src")
if not os.path.exists(base_path):
    os.makedirs(base_path)

def hash_password(password: str, salt: bytes = None) -> tuple[str, bytes]:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 500_000)
    return base64.b64encode(dk).decode(), base64.b64encode(salt).decode()

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    salt = base64.b64decode(stored_salt.encode())
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 500_000)
    return base64.b64encode(dk).decode() == stored_hash

def encrypt_key(master_password):
    key = Fernet.generate_key()
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest()))
    encrypted_key = cipher.encrypt(key)
    with open("secret.key", "wb") as f:
        f.write(encrypted_key)
    return key

def decrypt_key(master_password):
    with open("secret.key", "rb") as f:
        encrypted_key = f.read()
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest()))
    return cipher.decrypt(encrypted_key)

def generate_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    return hmac.compare_digest(generate_hmac(key, data), expected_hmac)

def update_vault_hmac(password: str):
    key_for_hmac = hashlib.sha256(password.encode()).digest()
    with open("vault.db", "rb") as f:
        content = f.read()
    hmac_value = generate_hmac(key_for_hmac, content)
    with open("vault.db.hmac", "wb") as f:
        f.write(hmac_value)

def delete_sensitive_data():
    try:
        os.remove("vault.db")
        os.remove("vault.db.hmac")
        os.remove("secret.key")
        os.remove("secret.key.hmac")
    except Exception as e:
        print(f"Error deleting sensitive data: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager - Mc-security | Login")
        self.resize(300, 200)
        self.setWindowIcon(QIcon(os.path.join(base_path, "lock.png")))
        with open(os.path.join(base_path, 'styles.qss'), 'r') as f:
            self.setStyleSheet(f.read())

        widget_page = QWidget()
        layout = QVBoxLayout(widget_page)

        title = QLabel("<b>Password Manager</b>")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addStretch()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setObjectName("password-input")
        self.password_input.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("One-Time Password")
        self.otp_input.setObjectName("otp-input")
        layout.addWidget(self.otp_input)

        login_btn = QPushButton("Login")
        login_btn.setObjectName("login")
        login_btn.clicked.connect(lambda: self.login(self.password_input.text(), self.otp_input.text()))
        layout.addWidget(login_btn)

        self.setCentralWidget(widget_page)

        if not os.path.exists("vault.db"):
            new_password_dialog = CreatePasswordDialog()
            if new_password_dialog.exec() == QDialog.DialogCode.Accepted:
                password = new_password_dialog.get_data()
                if password:
                    password_hash, salt = hash_password(password)
                    otp_secret = pyotp.random_base32()
                    otp_dialog = CreateOTPDialog(otp_secret)
                    if otp_dialog.exec() == QDialog.DialogCode.Accepted:
                        otp_secret = otp_dialog.get_secret()
                    else:
                        sys.exit(0)

                    with sqlite3.connect("vault.db") as conn:
                        cursor = conn.cursor()
                        cursor.execute("CREATE TABLE IF NOT EXISTS vault (password TEXT, salt TEXT, otp_secret TEXT)")
                        cursor.execute("INSERT INTO vault (password, salt, otp_secret) VALUES (?, ?, ?)",
                                       (password_hash, salt, otp_secret))
                        conn.commit()
                        cursor.execute("""CREATE TABLE IF NOT EXISTS accounts (
                            name TEXT, site TEXT, username TEXT, password TEXT
                        )""")
                        conn.commit()

                    key_for_hmac = hashlib.sha256(password.encode()).digest()
                    with open("vault.db", "rb") as f:
                        content = f.read()
                    hmac_value = generate_hmac(key_for_hmac, content)
                    with open("vault.db.hmac", "wb") as f:
                        f.write(hmac_value)

                    if not os.path.exists("secret.key"):
                        key = Fernet.generate_key()
                        cipher_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
                        cipher = Fernet(cipher_key)
                        encrypted_key = cipher.encrypt(key)
                        with open("secret.key", "wb") as key_file:
                            key_file.write(encrypted_key)

                        with open("secret.key", "rb") as f:
                            key_content = f.read()
                        key_hmac = generate_hmac(hashlib.sha256(password.encode()).digest(), key_content)
                        with open("secret.key.hmac", "wb") as f:
                            f.write(key_hmac)
                        del key, cipher_key, cipher, encrypted_key

                else:
                    sys.exit(0)
            else:
                sys.exit(0)

    def login(self, password, otp_code):
        key_for_hmac = hashlib.sha256(password.encode()).digest()

        with open("vault.db", "rb") as f:
            vault_content = f.read()
        with open("vault.db.hmac", "rb") as f:
            vault_hmac = f.read()
        if not verify_hmac(key_for_hmac, vault_content, vault_hmac):
            QMessageBox.critical(self, "Error", "Vault file altered. For security, data will be deleted.")
            delete_sensitive_data()
            sys.exit(1)

        with open("secret.key", "rb") as f:
            secret_content = f.read()
        with open("secret.key.hmac", "rb") as f:
            secret_hmac = f.read()
        if not verify_hmac(key_for_hmac, secret_content, secret_hmac):
            QMessageBox.critical(self, "Error", "Secret key file altered. For security, data will be deleted.")
            delete_sensitive_data()
            sys.exit(1)

        with sqlite3.connect("vault.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password, salt, otp_secret FROM vault")
            row = cursor.fetchone()
            if row:
                stored_hash, stored_salt, otp_secret = row
                if verify_password(password, stored_hash, stored_salt):
                    with open("secret.key", "rb") as f:
                        encrypted_key = f.read()
                    cipher_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
                    key = Fernet(cipher_key).decrypt(encrypted_key)
                    self.cipher = Fernet(key)

                    totp = pyotp.TOTP(otp_secret)
                    if totp.verify(otp_code):
                        self.master_password = password
                        self.open_vault(self.cipher)
                    else:
                        QMessageBox.critical(self, "Rejected", "Invalid OTP code")
                else:
                    QMessageBox.critical(self, "Rejected", "Incorrect password")

    def open_vault(self, cipher):
        self.vault_window = VaultWindow(cipher, self.master_password)
        self.vault_window.show()
        self.close()

class CreatePasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Create a Password")
        self.setWindowIcon(QIcon(os.path.join(base_path, "key.png")))
        layout = QFormLayout(self)

        info = QLabel("Please create a strong password to unlock the manager.")
        layout.addWidget(info)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.check_strength)
        layout.addRow(self.password_input)

        self.strength_label = QLabel("Password strength:")
        layout.addWidget(self.strength_label)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        layout.addWidget(self.strength_bar)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        layout.addWidget(self.buttons)

    def check_strength(self, password: str):
        if not password:
            self.strength_bar.setValue(0)
            self.strength_bar.setStyleSheet("")
            return

        results = zxcvbn.zxcvbn(password)
        score = results['score']
        percentage = (score + 1) * 20
        self.strength_bar.setValue(percentage)

        if percentage <= 25:
            color = "red"
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        elif percentage <= 50:
            color = "yellow"
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        elif percentage <= 75:
            color = "lightgreen"
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        else:
            color = "green"
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)

        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
            }}
            QProgressBar {{
                text-align: center;
            }}
        """)

    def get_data(self):
        return self.password_input.text()

class CreateOTPDialog(QDialog):
    def __init__(self, otp_secret):
        super().__init__()
        self.setWindowTitle("Setup OTP")
        self.setWindowIcon(QIcon(os.path.join(base_path, "password.png")))
        self.otp_secret = otp_secret
        self.totp = pyotp.TOTP(otp_secret)
        layout = QFormLayout(self)

        info = QLabel("Scan this QR code with Google Authenticator or equivalent.\n"
                      "Then enter an OTP code to verify setup.")
        info.setWordWrap(True)
        layout.addWidget(info)

        uri = self.totp.provisioning_uri(name="PasswordManager", issuer_name="Mc-gabys Security")
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        pixmap = QPixmap()
        pixmap.loadFromData(buffer.getvalue())

        qr_label = QLabel()
        qr_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(qr_label)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter OTP code")
        layout.addRow("OTP Code:", self.otp_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.verify_code)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def verify_code(self):
        if self.totp.verify(self.otp_input.text().strip()):
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Invalid OTP code.")

    def get_secret(self):
        return self.otp_secret

class VaultWindow(QMainWindow):
    def __init__(self, cipher, master_password):
        super().__init__()
        self.setWindowTitle("Password Manager - Mc-security | Vault")
        self.resize(500, 400)
        self.setWindowIcon(QIcon(os.path.join(base_path, "unlock.png")))
        with open(os.path.join(base_path, 'styles.qss'), 'r') as f:
            self.setStyleSheet(f.read())

        self.cipher = cipher
        self.master_password = master_password

        widget_page = QWidget()
        layout = QVBoxLayout(widget_page)

        title = QLabel("<b>Password Manager</b>")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addStretch()

        self.account_list = QTreeWidget()
        self.account_list.setHeaderLabels(["Name", "Site", "Username", "Password"])
        with sqlite3.connect("vault.db") as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS accounts (name TEXT, site TEXT, username TEXT, password TEXT)")
            cursor.execute("SELECT name, site, username, password FROM accounts")
            for name, site, username, password in cursor.fetchall():
                try:
                    decrypted_name = self.cipher.decrypt(name).decode()
                    decrypted_site = self.cipher.decrypt(site).decode()
                    decrypted_user = self.cipher.decrypt(username).decode()
                    decrypted_pass = self.cipher.decrypt(password).decode()
                except Exception:
                    decrypted_name = decrypted_site = decrypted_user = decrypted_pass = "[Error]"
                QTreeWidgetItem(self.account_list, (decrypted_name, decrypted_site, decrypted_user, decrypted_pass))
        layout.addWidget(self.account_list)
        layout.addStretch()

        add_btn = QPushButton("Add Account")
        add_btn.setObjectName("add")
        add_btn.clicked.connect(self.add_account)
        layout.addWidget(add_btn)

        remove_btn = QPushButton("Remove Account")
        remove_btn.setObjectName("rm")
        remove_btn.clicked.connect(self.remove_account)
        layout.addWidget(remove_btn)

        self.setCentralWidget(widget_page)

    def add_account(self):
        dialog = AddAccountDialog()
        if dialog.exec():
            name, site, username, password = dialog.get_data()
            if name and username and password:
                with sqlite3.connect("vault.db") as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO accounts (name, site, username, password) VALUES (?, ?, ?, ?)",
                        (self.cipher.encrypt(name.encode()), self.cipher.encrypt(site.encode()),
                         self.cipher.encrypt(username.encode()), self.cipher.encrypt(password.encode()))
                    )
                    conn.commit()
                QTreeWidgetItem(self.account_list, (name, site, username, password))
                update_vault_hmac(self.master_password)
            else:
                QMessageBox.warning(self, "Incomplete", "Please fill in the required fields.")

    def remove_account(self):
        dialog = RemoveAccountDialog(self.cipher)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            account_name = dialog.get_data()
            with sqlite3.connect("vault.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT rowid, name FROM accounts")
                for rowid, enc_name in cursor.fetchall():
                    try:
                        if self.cipher.decrypt(enc_name).decode() == account_name:
                            cursor.execute("DELETE FROM accounts WHERE rowid = ?", (rowid,))
                            conn.commit()
                            break
                    except Exception:
                        continue

            root = self.account_list.invisibleRootItem()
            for i in range(root.childCount()):
                item = root.child(i)
                if item.text(0) == account_name:
                    root.removeChild(item)
                    break
            update_vault_hmac(self.master_password)

class AddAccountDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Add Account")
        layout = QFormLayout(self)

        self.name_input = QLineEdit()
        self.site_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()

        layout.addRow("Name*:", self.name_input)
        layout.addRow("Site:", self.site_input)
        layout.addRow("Username*:", self.username_input)
        layout.addRow("Password*:", self.password_input)

        info = QLabel("Fields marked with * are required")
        layout.addWidget(info)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_data(self):
        return self.name_input.text(), self.site_input.text(), self.username_input.text(), self.password_input.text()

class RemoveAccountDialog(QDialog):
    def __init__(self, cipher):
        super().__init__()
        self.setWindowTitle("Remove Account")
        self.cipher = cipher
        layout = QFormLayout(self)

        self.account_selector = QComboBox()
        with sqlite3.connect("vault.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM accounts")
            for (enc_name,) in cursor.fetchall():
                try:
                    self.account_selector.addItem(self.cipher.decrypt(enc_name).decode())
                except Exception:
                    continue
        layout.addRow("Select account:", self.account_selector)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_data(self):
        return self.account_selector.currentText()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
