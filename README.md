# Simple JWKS Server (Project 3 - Enhanced Security & User Management)

A JSON Web Key Set (JWKS) server built with Python and Flask. This updated version of the server builds upon the SQLite integration by adding advanced security features, including AES encryption for private keys, user registration with Argon2 password hashing, authentication request logging, and a rate limiter.

## Features
* **Database Persistence:** Uses SQLite to securely store keys, users, and logs (`totally_not_my_privateKeys.db`).
* **AES Encryption:** Private keys are symmetrically encrypted in the database using AES-GCM to ensure they are never stored in plaintext.
* **User Registration (`/register`):** Allows users to register. Generates secure UUIDv4 passwords and stores them using Argon2 hashing.
* **Authentication Logging:** Records the IP address, timestamp, and user ID for every successful authentication request.
* **Rate Limiting:** Protects the `/auth` endpoint by limiting requests to 10 per second, returning a `429 Too Many Requests` status when exceeded.
* **JWT Generation & JWKS Endpoint:** Signs tokens using RSA-256 and serves valid, unexpired public keys in a standardized JWKS format.

## Setup Instructions

1. Clone the Repository**
```powershell
git clone https://github.com/b3gula/Simple-JWSK-server.git
cd Simple-JWSK-server

2. Create a Virtual Environment
PowerShell
python -m venv venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\venv\Scripts\activate

3. Install Dependencies
PowerShell
pip install -r requirements.txt

4. Set Environment Variables
The server requires a secret key for AES encryption. Set this in your terminal before running the server:
PowerShell
$env:NOT_MY_KEY="your_super_secret_encryption_key_here"


How to Run the Program
1. Run the program mannually
Execute the command: "python main.py"
The server will run on http://127.0.0.1:8080/jwks

2. Run the Gradebot
Step 1: Download the Gradebot from the test client: https://github.com/jh125486/CSCE3550/releases
Step 2: Move the gradebot.exe file directly into your Simple-JWKS-Server folder (it must be in the same folder as main.py).
Execute the following command in your terminal:
.\gradebot.exe project-3 --run "python main.py"

Testing & Coverage
To view the test coverage of the server after running the tests:
PowerShell
python -m coverage run -m unittest test_server.py
python -m coverage report

Project Structure
main.py: The primary Flask application, routing, JWT logic, rate limiting, and user registration endpoints.

database.py: A dedicated module handling SQLite database connections, parameterized queries, and AES-GCM encryption/decryption.

test_server.py: The unit test suite for the server endpoints, including rate limiter and registration tests.

requirements.txt: List of necessary Python libraries (Flask, PyJWT, cryptography, argon2-cffi).

.gitignore: Excludes venv/, executables, and the .db file from the repository.
