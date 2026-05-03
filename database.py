"""
Database module for handling SQLite connections, queries, and AES encryption.
Includes robust error handling for connection reliability.
"""
import sqlite3
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

DB_FILE = os.environ.get('DB_FILE', 'totally_not_my_privateKeys.db')

def get_aes_key() -> bytes:
    """
    Derives a secure 32-byte AES key from the NOT_MY_KEY environment variable.

    Returns:
        bytes: A 32-byte hash representing the AES key.
    """
    raw_key = os.environ.get('NOT_MY_KEY', 'default_secret_key_for_testing')
    return hashlib.sha256(raw_key.encode('utf-8')).digest()

def init_db():
    """
    Initializes the SQLite database and creates the keys, users, and auth_logs tables.
    Includes error handling for connection reliability.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Removed the 'iv' column; IV is now prepended to the key BLOB.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            ''')
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
    except sqlite3.Error as e:
        logging.error(f"Database connection error during init_db: {e}")

def is_db_empty() -> bool:
    """
    Checks if the keys table has any records.

    Returns:
        bool: True if the table is empty, False otherwise.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM keys')
            return cursor.fetchone()[0] == 0
    except sqlite3.Error as e:
        logging.error(f"Database error during is_db_empty: {e}")
        return True

def save_key_to_db(pem: bytes, expiry: int):
    """
    Encrypts a serialized RSA private key and saves it to the database.
    Prepends the 12-byte nonce (IV) to the ciphertext.

    Args:
        pem (bytes): The private key in PEM format.
        expiry (int): The Unix timestamp when the key expires.
    """
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pem, None)
    
    # Combine nonce and ciphertext into a single BLOB
    encrypted_blob = nonce + ciphertext

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_blob, expiry))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error during save_key_to_db: {e}")

def get_valid_keys_from_db(current_time: int) -> list:
    """
    Retrieves and decrypts all valid (unexpired) keys from the database.

    Args:
        current_time (int): The current Unix timestamp.

    Returns:
        list: A list of tuples containing (kid, decrypted_pem).
    """
    valid_keys = []
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (current_time,))
            rows = cursor.fetchall()

        aesgcm = AESGCM(get_aes_key())
        for row in rows:
            kid, encrypted_blob = row
            
            # Extract the 12-byte nonce and the rest of the ciphertext
            nonce = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]
            
            try:
                pem = aesgcm.decrypt(nonce, ciphertext, None)
                valid_keys.append((kid, pem))
            except Exception as e:
                logging.error(f"Decryption failed for key {kid}: {e}")
                continue
        return valid_keys
    except sqlite3.Error as e:
        logging.error(f"Database error during get_valid_keys_from_db: {e}")
        return valid_keys

def get_single_key_from_db(current_time: int, expired: bool = False):
    """
    Retrieves and decrypts a single key from the database.

    Args:
        current_time (int): The current Unix timestamp.
        expired (bool): Whether to retrieve an expired key instead of a valid one.

    Returns:
        tuple: (kid, decrypted_pem, exp) if found, else None.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if expired:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
            else:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1', (current_time,))
            row = cursor.fetchone()

        if not row:
            return None

        kid, encrypted_blob, exp = row
        aesgcm = AESGCM(get_aes_key())
        
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        try:
            pem = aesgcm.decrypt(nonce, ciphertext, None)
            return (kid, pem, exp)
        except Exception as e:
            logging.error(f"Decryption failed for key {kid}: {e}")
            return None
    except sqlite3.Error as e:
        logging.error(f"Database error during get_single_key_from_db: {e}")
        return None

def register_user(username: str, email: str, password_hash: str) -> bool:
    """
    Registers a new user in the database.

    Args:
        username (str): The requested username.
        email (str): The requested email.
        password_hash (str): The Argon2 hashed password.

    Returns:
        bool: True if successful, False if the username or email already exists.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                           (username, email, password_hash))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error during register_user: {e}")
        return False

def get_user_by_username(username: str):
    """
    Fetches a user ID and password hash by their username.

    Args:
        username (str): The username to query.

    Returns:
        tuple: (id, password_hash) if found, else None.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
    except sqlite3.Error as e:
        logging.error(f"Database error during get_user_by_username: {e}")
        return None

def log_auth_request(request_ip: str, user_id: int):
    """
    Logs an authentication request to the auth_logs table.

    Args:
        request_ip (str): The IP address making the request.
        user_id (int): The ID of the user (can be None).
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error during log_auth_request: {e}")