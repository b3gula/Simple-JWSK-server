Simple JWKS Server
A basic JSON Web Key Set (JWKS) server built with Python and Flask. This server provides a RESTful API to issue signed JSON Web Tokens (JWT) and serves public keys via a JWKS endpoint, supporting both valid and expired keys for testing purposes.

Features
JWT Generation: Signs tokens using RSA-256.
JWKS Endpoint: Serves public keys in a standardized JWKS format.
Key Rotation Simulation: Handles ?expired=true requests by signing with past-dated keys.
Automated Grading Compatibility: Structured to work with the gradebot testing client.

Setup Instructions
1. Clone the Repository
Bash
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
Step1: Run the program mannually
Execute the command: "python main.py"
The server will run on http://127.0.0.1:8080/jwks

Step 2: Run the Gradebot
Step 1: Download the Gradebot from the test client: https://github.com/jh125486/CSCE3550/releases
Step 2: Download the correct version of your machine and extract it into the same directory of the main directory
Execute the following command in your PowerShell terminal:
PowerShell
.\gradebot.exe project-1 --run "python main.py"

Testing & Coverage
To view the test coverage of the server after running the tests:
PowerShell
coverage report
Note: The project aims for at least 80% test coverage as per rubric requirements.

Project Structure
main.py: The primary Flask application and JWT logic.
requirements.txt: List of necessary Python libraries (Flask, PyJWT, cryptography).
.gitignore: Excludes venv/ and executables from the repository.
