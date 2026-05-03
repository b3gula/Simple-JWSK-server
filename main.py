"""
Main application module for the JWKS Server.
Handles API routing, JWT generation, user registration, and authentication.
"""
import time
import datetime
import uuid
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
import database
from collections import defaultdict

app = Flask(__name__)
ph = PasswordHasher()

class RateLimiter:
    """
    A simple in-memory rate limiter to control request frequency.
    """
    def __init__(self, window: float = 1.0, max_requests: int = 10):
        self.window = window
        self.max_requests = max_requests
        self.data = defaultdict(list)

    def is_limited(self, ip: str) -> bool:
        """
        Checks if a request from the given IP exceeds the rate limit.
        
        Args:
            ip (str): The IP address of the client.
            
        Returns:
            bool: True if limited, False otherwise.
        """
        current_time = time.time()
        self.data[ip] = [t for t in self.data[ip] if current_time - t < self.window]
        
        if len(self.data[ip]) >= self.max_requests:
            return True
            
        self.data[ip].append(current_time)
        return False

# Instantiate the rate limiter instance
limiter = RateLimiter()

def generate_key_pair(expired: bool = False):
    """
    Generates an RSA key and saves it securely to the database.
    
    Args:
        expired (bool): True to generate a key that is already expired.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expiry = int(time.time()) - 3600 if expired else int(time.time()) + 3600
    database.save_key_to_db(pem, expiry)

# Initialize DB on startup
database.init_db()

if database.is_db_empty():
    generate_key_pair(expired=False)
    generate_key_pair(expired=True)

@app.route('/')
def health_check():
    """Basic health check endpoint."""
    return "Server is running", 200

@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user with a generated UUID password hashed via Argon2.
    
    Returns:
        Response: JSON containing the generated password or an error.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({"error": "Invalid request parameters"}), 400

    username = data['username']
    email = data['email']
    
    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    success = database.register_user(username, email, password_hash)
    if success:
        return jsonify({"password": password}), 201
    return jsonify({"error": "User already exists"}), 409

@app.route('/.well-known/jwks.json', methods=['GET'])
@app.route('/jwks', methods=['GET'])
def jwks():
    """
    JWKS endpoint to retrieve all valid public keys.
    
    Returns:
        Response: JSON representation of the JWKS keys.
    """
    current_time = int(time.time())
    rows = database.get_valid_keys_from_db(current_time)

    valid_keys = []
    for kid, key_pem in rows:
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
    """
    Authentication endpoint that issues JWTs and logs requests.
    
    Returns:
        Response: Encoded JWT or an error message.
    """
    ip_address = request.remote_addr or "127.0.0.1"

    # 1. Rate Limiter execution
    if limiter.is_limited(ip_address):
        return "Too Many Requests", 429

    # 2. Extract User details
    username = None
    if request.authorization:
        username = request.authorization.username
    elif request.is_json and 'username' in request.json:
        username = request.json.get('username')

    user_id = None
    if username:
        user = database.get_user_by_username(username)
        if user:
            user_id = user[0]

    # 3. Log the successful request to the DB
    database.log_auth_request(ip_address, user_id)

    # 4. Handle Keys and JWT issuance
    is_expired_requested = request.args.get('expired') is not None
    current_time = int(time.time())

    row = database.get_single_key_from_db(current_time, expired=is_expired_requested)
    if not row:
        generate_key_pair(expired=is_expired_requested)
        row = database.get_single_key_from_db(current_time, expired=is_expired_requested)

    if not row:
        return "Appropriate key not found in database", 500

    kid, key_pem, exp = row
    private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

    headers = {"kid": str(kid)}
    payload = {
        "sub": username if username else "fake_user",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return token

if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')