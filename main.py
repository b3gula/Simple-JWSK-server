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

# Rate Limiter Setup
RATE_LIMIT_WINDOW = 1.0
MAX_REQUESTS = 10
rate_limit_data = defaultdict(list)

def is_rate_limited(ip):
    current_time = time.time()
    # Clean up timestamps older than 1 second
    rate_limit_data[ip] = [t for t in rate_limit_data[ip] if current_time - t < RATE_LIMIT_WINDOW]
    
    if len(rate_limit_data[ip]) >= MAX_REQUESTS:
        return True
        
    rate_limit_data[ip].append(current_time)
    return False


def generate_key_pair(expired=False):
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
    # Basic health check endpoint
    return "Server is running", 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({"error": "Invalid request parameters"}), 400

    username = data['username']
    email = data['email']
    
    # Generate secure UUIDv4 password
    password = str(uuid.uuid4())
    # Hash password with Argon2
    password_hash = ph.hash(password)

    success = database.register_user(username, email, password_hash)
    if success:
        return jsonify({"password": password}), 201
    return jsonify({"error": "User already exists"}), 409

@app.route('/.well-known/jwks.json', methods=['GET'])
@app.route('/jwks', methods=['GET'])
def jwks():
    """JWKS endpoint to retrieve all valid public keys."""
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
    ip_address = request.remote_addr

    # Return 429 if too many requests)
    if is_rate_limited(ip_address):
        return "Too Many Requests", 429

    # Extract User details
    username = None
    if request.authorization:
        username = request.authorization.username
    elif request.is_json and 'username' in request.json:
        username = request.json.get('username')

    user_id = None
    if username:
        user = database.get_user_by_username(username)
        if user:
            user_id = user[0]  # The first element in the DB row is the ID

    # 3. Log the successful request to the DB
    database.log_auth_request(ip_address, user_id)

    # 4. Handle Keys and JWT issuance
    is_expired_requested = request.args.get('expired') is not None
    current_time = int(time.time())

    row = database.get_single_key_from_db(current_time, expired=is_expired_requested)
    if not row:
        generate_key_pair(expired=is_expired_requested)
        row = database.get_single_key_from_db(current_time, expired=is_expired_requested)

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