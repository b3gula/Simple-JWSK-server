"""
Database module for handling SQLite connections, queries, and AES encryption.
This module incorporates robust error handling and comprehensive logging practices 
to ensure production-readiness and reliability.
"""
import sqlite3
import os
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configure robust logging for monitoring and debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_FILE = os.environ.get('DB_FILE', 'totally_not_my_privateKeys.db')

def get_aes_key() -> bytes:
    """Derives a secure 32-byte AES key from the NOT_MY_KEY environment variable."""
    raw_key = os.environ.get('NOT_MY_KEY', 'default_secret_key_for_testing')
    return hashlib.sha256(raw_key.encode('utf-8')).digest()

def init_db():
    """Initializes the SQLite database with proper schema. Handles connection issues gracefully."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Keys table explicitly without the 'iv' column; IV is prepended
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            ''')
            # Users table for registration
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
            # Auth logs table for monitoring requests
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
            logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed due to connection or syntax error: {e}", exc_info=True)

def is_db_empty() -> bool:
    """Checks if the keys table has any records."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM keys')
            result = cursor.fetchone()
            return result[0] == 0 if result else True
    except sqlite3.Error as e:
        logger.error(f"Error checking if database is empty: {e}", exc_info=True)
        return True

def save_key_to_db(pem: bytes, expiry: int):
    """Encrypts a private key (prepending the IV to the BLOB) and saves it securely."""
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    
    # Complex Logic: Encrypt the PEM and prepend the 12-byte nonce directly to the ciphertext.
    # This avoids needing a separate IV column in the database schema and ensures IV travels with data.
    ciphertext = aesgcm.encrypt(nonce, pem, None)
    encrypted_blob = nonce + ciphertext

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_blob, expiry))
            conn.commit()
            logger.info("Key successfully encrypted and saved to database.")
    except sqlite3.Error as e:
        logger.error(f"Failed to securely save key to database: {e}", exc_info=True)

def get_valid_keys_from_db(current_time: int) -> list:
    """Retrieves and decrypts all valid keys."""
    valid_keys = []
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (current_time,))
            rows = cursor.fetchall()

        aesgcm = AESGCM(get_aes_key())
        for row in rows:
            kid, encrypted_blob = row
            nonce = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]
            try:
                pem = aesgcm.decrypt(nonce, ciphertext, None)
                valid_keys.append((kid, pem))
            except Exception as e:
                logger.warning(f"Decryption failed for key {kid}, skipping: {e}")
                continue
        return valid_keys
    except sqlite3.Error as e:
        logger.error(f"Database query error while fetching valid keys: {e}", exc_info=True)
        return valid_keys

def get_single_key_from_db(current_time: int, expired: bool = False):
    """Retrieves the first successfully decrypted key matching the expiry criteria."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if expired:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp <= ?', (current_time,))
            else:
                cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ?', (current_time,))
            
            rows = cursor.fetchall()

        aesgcm = AESGCM(get_aes_key())
        for row in rows:
            kid, encrypted_blob, exp = row
            nonce = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]
            try:
                pem = aesgcm.decrypt(nonce, ciphertext, None)
                return (kid, pem, exp)
            except Exception as e:
                logger.warning(f"Failed to decrypt key {kid}, attempting next available key: {e}")
                continue
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error during single key retrieval: {e}", exc_info=True)
        return None

def register_user(username: str, email: str, password_hash: str) -> bool:
    """Registers a new user in the database with extensive integrity checking."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                           (username, email, password_hash))
            conn.commit()
            logger.info(f"User {username} registered successfully.")
            return True
    except sqlite3.IntegrityError:
        logger.warning(f"Registration failed: User {username} or email {email} already exists.")
        return False
    except sqlite3.Error as e:
        logger.error(f"Critical database error during user registration: {e}", exc_info=True)
        return False

def get_user_by_username(username: str):
    """Fetches a user ID and password hash by their username."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Error fetching user {username}: {e}", exc_info=True)
        return None

def log_auth_request(request_ip: str, user_id: int):
    """Logs an authentication request securely into the auth_logs table."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
            conn.commit()
            logger.info(f"Auth request logged for IP {request_ip}, User ID: {user_id}")
    except sqlite3.Error as e:
        logger.error(f"Error logging authentication request: {e}", exc_info=True)