import time
import datetime
import sqlite3
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
DB_FILE = 'totally_not_my_privateKeys.db'

def init_db():
    """Initializes the database table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# UPGRADED generate_key_pair function
def generate_key_pair(expired=False):
    """Generates an RSA key and saves it to the SQLite database."""
    # Generate the raw RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize the key to PEM format so SQLite can store it
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Determine Expiry
    if expired:
        expiry = int(time.time()) - 3600
    else:
        expiry = int(time.time()) + 3600

    # Save to Database instead of keys.append()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiry))
    conn.commit()
    conn.close()

# Initialize DB and pre-generate the required keys
init_db()
# Generate initial keys if the DB is empty
conn = sqlite3.connect(DB_FILE)
if conn.execute('SELECT COUNT(*) FROM keys').fetchone()[0] == 0:
    generate_key_pair(expired=False) # Valid key
    generate_key_pair(expired=True)  # Expired key
conn.close()

@app.route('/')
def health_check():
    return "Server is running", 200

@app.route('/.well-known/jwks.json', methods=['GET'])
@app.route('/jwks', methods=['GET'])
def jwks():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(time.time())
    
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (current_time,))
    rows = cursor.fetchall()
    conn.close()

    valid_keys = []
    for row in rows:
        kid, key_pem = row
        # Convert PEM back to an RSA object to get public numbers
        private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
        pn = private_key.public_key().public_numbers()
        
        valid_keys.append({
            "kid": str(kid), 
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": jwt.utils.to_base64url_uint(pn.n).decode('utf-8'),
            "e": jwt.utils.to_base64url_uint(pn.e).decode('utf-8'),
        })
        
    return jsonify(keys=valid_keys)

@app.route('/auth', methods=['POST'])
def auth():
    is_expired_requested = request.args.get('expired') is not None
    current_time = int(time.time())
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if is_expired_requested:
        cursor.execute('SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
    else:
        cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1', (current_time,))
        
    row = cursor.fetchone()
    conn.close()
    
    # Fallback in case we somehow run out of keys in the DB
    if not row:
        generate_key_pair(expired=is_expired_requested)
        # Re-query after generating
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        operator = "<=" if is_expired_requested else ">"
        cursor.execute(f'SELECT kid, key, exp FROM keys WHERE exp {operator} ? LIMIT 1', (current_time,))
        row = cursor.fetchone()
        conn.close()
        
    kid, key_pem, exp = row
    private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
    
    headers = {"kid": str(kid)}
    payload = {
        "sub": "fake_user",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return token

if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')