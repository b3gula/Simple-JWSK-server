# Simple JWKS Server (Project 2 - SQLite Integration)

A basic JSON Web Key Set (JWKS) server built with Python and Flask. This updated version of the server integrates a **SQLite database** to securely persist generated RSA keys to disk. This ensures keys are available even after server restarts, while utilizing parameterized SQL queries to protect against SQL injection attacks.

## Features
Database Persistence:Uses SQLite to securely store and manage RSA keys (`totally_not_my_privateKeys.db`).
JWT Generation: Signs tokens using RSA-256 and fetches the appropriate key from the database.
JWKS Endpoint: Serves valid, unexpired public keys in a standardized JWKS format.
Key Rotation Simulation: Handles `?expired=true` requests by querying the database for past-dated keys.
Automated Grading Compatibility: Structured to work with the CSCE3550 gradebot testing client.

## Setup Instructions

1. Clone the Repository
powershell
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


How to Run the Program
1. Run the program mannually
Execute the command: "python main.py"
The server will run on http://127.0.0.1:8080/jwks

2. Run the Gradebot
Step 1: Download the Gradebot from the test client: https://github.com/jh125486/CSCE3550/releases
Step 2: Move the gradebot.exe file directly into your Simple-JWKS-Server folder (it must be in the same folder as main.py).
Execute the following command in your terminal:
.\gradebot.exe project-2 --run "python main.py"

Testing & Coverage
To view the test coverage of the server after running the tests:
PowerShell
python -m coverage run -m unittest test_server.py
python -m coverage report

Project Structure
main.py: The primary Flask application, routing, and JWT logic.
database.py: A dedicated module handling all SQLite database connections and parameterized queries.
test_server.py: The unit test suite for the server endpoints.
requirements.txt: List of necessary Python libraries (Flask, PyJWT, cryptography).
.gitignore: Excludes venv/, executables, and the .db file from the repository.
