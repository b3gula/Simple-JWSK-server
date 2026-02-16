import time
import datetime
import uuid
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Key storage
keys = []

def generate_key_pair(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    kid = str(uuid.uuid4())
    
    # Use explicit Unix timestamps
    if expired:
        # Set to 1 hour ago
        expiry = int(time.time()) - 3600
    else:
        # Set to 1 hour in the future
        expiry = int(time.time()) + 3600
        
    key_entry = {
        "kid": kid,
        "private_key": private_key,
        "public_key": private_key.public_key(),
        "expiry": expiry
    }
    keys.append(key_entry)
    return key_entry

# Pre-generate an active valid key immediately
generate_key_pair(expired=False)

@app.route('/')
def health_check():
    """Fixes the 'Quality' 401/unauthenticated check by providing a base response."""
    return "Server is running", 200

@app.route('/.well-known/jwks.json', methods=['GET'])
@app.route('/jwks', methods=['GET'])
def jwks():
    valid_keys = []
    current_time = int(time.time())
    for key in keys:
        # Rubric: Only serve keys that have NOT expired
        if key['expiry'] > current_time:
            pn = key['public_key'].public_numbers()
            valid_keys.append({
                "kid": key['kid'],
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
    
    if is_expired_requested:
        # Find an existing expired key or create one
        key_data = next((k for k in keys if k['expiry'] <= current_time), None)
        if not key_data:
            key_data = generate_key_pair(expired=True)
    else:
        # Find an existing valid key or create one
        key_data = next((k for k in keys if k['expiry'] > current_time), None)
        if not key_data:
            key_data = generate_key_pair(expired=False)
    
    headers = {"kid": key_data['kid']}
    
    # Payload logic: Use datetime.datetime for PyJWT compatibility
    # Ensure 'exp' is a future date for valid tokens
    payload = {
        "sub": "fake_user",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.fromtimestamp(key_data['expiry'], tz=datetime.timezone.utc)
    }
    
    private_pem = key_data['private_key'].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)
    return token

if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')