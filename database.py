"""
Database module for handling SQLite connections, queries, and AES encryption.
"""
import sqlite3
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Use environment variable for DB configuration
DB_FILE = os.environ.get('DB_FILE', 'totally_not_my_privateKeys.db')

def get_aes_key():
    """Derives a secure 32-byte AES key from the NOT_MY_KEY environment variable."""
    raw_key = os.environ.get('NOT_MY_KEY', 'default_secret_key_for_testing')
    # Hash the key to guarantee it is exactly 32 bytes (required by AES)
    return hashlib.sha256(raw_key.encode('utf-8')).digest()

def init_db():
    """Initializes the SQLite database and creates the keys, users, and auth_logs tables."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Table for encrypted keys (Added the 'iv' column per instructions)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL,
                iv BLOB NOT NULL
            )
        ''')
        # Table for user registration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        # Table for logging auth requests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

def is_db_empty():
    """Checks if the keys table has any records."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM keys')
        return cursor.fetchone()[0] == 0

def save_key_to_db(pem: bytes, expiry: int):
    """Encrypts a serialized RSA private key and saves it to the database."""
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)  # Secure IV/Nonce
    ciphertext = aesgcm.encrypt(nonce, pem, None)

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO keys (key, exp, iv) VALUES (?, ?, ?)', (ciphertext, expiry, nonce))
        conn.commit()

def get_valid_keys_from_db(current_time):
    """Retrieves and decrypts all valid (unexpired) keys from the database."""
    valid_keys = []
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT kid, key, iv FROM keys WHERE exp > ?', (current_time,))
        rows = cursor.fetchall()

    aesgcm = AESGCM(get_aes_key())
    for row in rows:
        kid, ciphertext, nonce = row
        try:
            pem = aesgcm.decrypt(nonce, ciphertext, None)
            valid_keys.append((kid, pem))
        except Exception:
            continue
    return valid_keys

def get_single_key_from_db(current_time, expired=False):
    """Retrieves and decrypts a single key from the database based on the expired flag."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute('SELECT kid, key, exp, iv FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
        else:
            cursor.execute('SELECT kid, key, exp, iv FROM keys WHERE exp > ? LIMIT 1', (current_time,))
        row = cursor.fetchone()

    if not row:
        return None

    kid, ciphertext, exp, nonce = row
    aesgcm = AESGCM(get_aes_key())
    try:
        pem = aesgcm.decrypt(nonce, ciphertext, None)
        return (kid, pem, exp)
    except Exception:
        return None

def register_user(username, email, password_hash):
    """Registers a new user in the database."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                           (username, email, password_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def get_user_by_username(username):
    """Fetches a user ID and password hash by their username."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        return cursor.fetchone()

def log_auth_request(request_ip, user_id):
    """Logs an authentication request to the auth_logs table."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
        conn.commit()