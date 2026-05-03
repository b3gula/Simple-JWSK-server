"""
Main application module for the JWKS Server.
Handles API routing, JWT generation, user registration, and authentication.
Includes enhancements for scalability and error handling.
"""
import time
import datetime
import uuid
import logging
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
import database
from collections import defaultdict

# Set up logging for the main app
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
ph = PasswordHasher()

class MemoryRateLimiter:
    """
    In-memory rate limiter to control request frequency.
    
    PRODUCTION NOTE: This implementation uses an in-memory defaultdict. 
    While straightforward and suitable for a single-node deployment, 
    it is highly recommended to migrate to a more robust storage mechanism 
    (e.g., Redis) for proper distributed scalability and thread-safety in production.
    """
    def __init__(self, window: float = 1.0, max_requests: int = 10):
        self.window = window
        self.max_requests = max_requests
        self.data = defaultdict(list)

    def is_limited(self, ip: str) -> bool:
        """
        Checks if a request from the given IP exceeds the rate limit.
        Uses a sliding time window mechanism to drop old timestamps.
        """
        current_time = time.time()
        
        # Complex Logic: List comprehension filters out timestamps that fall outside 
        # the current sliding window, preventing memory leaks and enforcing rate correctly.
        self.data[ip] = [t for t in self.data[ip] if current_time - t < self.window]
        
        if len(self.data[ip]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return True
            
        self.data[ip].append(current_time)
        return False

# Instantiate the rate limiter instance globally for the server lifecycle
limiter = MemoryRateLimiter()

def generate_key_pair(expired: bool = False):
    """Generates an RSA key and delegates saving logic to the database module."""
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

# Initialize DB safely on startup
database.init_db()

# Ensure there are keys available for testing immediately
if database.is_db_empty():
    logger.info("Database is empty. Pre-generating initial keys.")
    generate_key_pair(expired=False)
    generate_key_pair(expired=True)

@app.route('/')
def health_check():
    """Basic health check endpoint."""
    return "Server is running", 200

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user, hashes a generated UUID password via Argon2."""
    data = request.get_json(silent=True, force=True)
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
    """JWKS endpoint to retrieve and format all valid public keys."""
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
    """Authentication endpoint: Rate limits, logs requests, and issues JWTs."""
    ip_address = request.remote_addr or "127.0.0.1"

    # Enforce Rate Limiting Before Any Other Processing
    if limiter.is_limited(ip_address):
        return "Too Many Requests", 429

    # Robust Username Extraction (handles Basic Auth and JSON bodies without strict headers)
    username = None
    if request.authorization and request.authorization.username:
        username = request.authorization.username
    else:
        # Use force=True to ensure JSON parsing even if Content-Type header is missing
        req_data = request.get_json(silent=True, force=True)
        if req_data and 'username' in req_data:
            username = req_data['username']

    # Retrieve User ID if user exists
    user_id = None
    if username:
        user = database.get_user_by_username(username)
        if user:
            user_id = user[0]

    # Log the successfully accepted request
    database.log_auth_request(ip_address, user_id)

    # Issue token using appropriate key
    is_expired_requested = request.args.get('expired') is not None
    current_time = int(time.time())

    row = database.get_single_key_from_db(current_time, expired=is_expired_requested)
    
    # Fallback to generate a new key if none is found
    if not row:
        logger.warning("No appropriate key found. Generating on the fly.")
        generate_key_pair(expired=is_expired_requested)
        row = database.get_single_key_from_db(current_time, expired=is_expired_requested)

    if not row:
        logger.error("Failed to retrieve or generate a key.")
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