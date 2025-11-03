# Hashing and Encoding Utility API

## Description

This project is a secure Hashing & Encoding REST API designed with a full DevSecOps pipeline and production-grade security practices.
It includes automated security controls, OAuth2 authentication, JWT-based session management, software supply-chain scanning, static code analysis, and secret detection.
The objective was to demonstrate how real-world security standards can be applied even in a small API: CI/CD enforcement, dependency scanning, unit testing with coverage thresholds, rate limiting, and secure database interactions.

## Security highlights
- OAuth2 (GitLab) + JWT authentication
Provides secure, stateless user identification without storing sessions on the server.

- Rate limiting on every API endpoint
Protects against brute-force attacks and basic DoS attempts on hashing operations.

- SAST, SCA and secret-scanning integrated into CI/CD
  - bandit → static analysis of Python code
  - pip-audit → dependency vulnerability scanning
  - gitleaks & truffleHog → secret detection

- 85% minimum test coverage enforced : If coverage drops below threshold, pipeline fails → security and quality gate

- Secure database handling with SQLModel ORM
    - Parameterized queries
    - Auto-escaping
    - Eliminates risk of SQL injection

- Separated CI dependencies vs runtime dependencies
Reduces attack surface and avoids shipping heavy security tooling inside production containers.

- .env file required
Ensures credentials, OAuth2 secrets, and DB strings never appear in code or Git history.


## Stack

This project is built using the following technologies and tools:

- Python 3.11 — Main programming language.
- FastAPI — Modern, async web framework used to build the API.
- SQLite — Lightweight embedded database managed via SQLModel.
- SQLModel — ORM combining SQLAlchemy and Pydantic for database interactions.
- Uvicorn — ASGI server used to run the FastAPI application.
- OAuth2 (GitLab) – Authentication system using GitLab OAuth2
- JWT (JSON Web Tokens) – For stateless session management
- pytest — Unit testing framework.
- flake8 — Linter to ensure code quality and style consistency.
- bandit — Static Application Security Testing tool to find common security issues in Python code.
- pipaudit — Software Composition Analysis, checks Python dependencies for known vulnerabilities.
- truffleHog — Tool to detect hardcoded secrets in the codebase.
- gitleaks — Secret scanning tool for Git repositories.
- Gitlab Oauth2

## Prerequisites

Run and tested with Python 3.11.13

A .venv is recommended, every library are in the 'requirements.txt'


## Installation

1.  Clone this repository:

2.  Create and activate a Python virtual environment:

    ```bash
    python -m venv .venv
    ```
    ```bash
    source .venv/bin/activate
    ```
3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```


4. Setting the enviornnemnt variables :

    In this step you need to create a .env file at the root of the project and follow the .env.example file variables

5. Install docker

## Running the Application

### Locally

To run the FastAPI application locally using Uvicorn:
```bash
  uvicorn main:app --reload
```

### Docker 
```bash
  docker build -t devsecops .
```

```bash
  docker run -p 8000:8000 devsecops
```


The application will typically be available at http://127.0.0.1:8000. 

The database "database.sqlite3" will be automatically created in the root directory if not already present.

The interactive API documentation (Swagger UI) can be found at http://127.0.0.1:8000/docs.


## OAuth2 Authentication Flow (GitLab)
The project implements a secure OAuth2 authentication flow using GitLab as the identity provider. The process is designed to ensure both user identity verification and CSRF protection, while providing a JWT-based session mechanism for subsequent API requests.

Flow Overview:
1. Frontend Initiates Login

    The frontend calls a backend endpoint to obtain a custom GitLab login URL, which includes the GitLab Client ID and a randomly generated state token for CSRF protection.


2. User Authentication via GitLab

    The frontend redirects the user to the GitLab login page using the provided URL. After authentication, GitLab redirects back to the frontend with an authorization code and the state.


3. Code Exchange with the Backend

    The frontend sends the received code and state to a secure POST endpoint on the backend. The backend verifies the validity of the state (CSRF protection), then requests an access token from GitLab using the gitlab project credentials (id and secret) and the code.


4. User Information Retrieval

    With the access token, the backend calls the GitLab API to retrieve user information (ID, username, and email). If the user does not already exist in the local database, they are created.


5. JWT Generation

    The backend generates a JWT token containing the user's identity information and returns it to the frontend.


6. Frontend Stores Token

    The frontend stores the JWT in local storage and includes it as a Bearer token in the Authorization header for all protected API requests.


7. Backend Verifies Token

    On every request to a protected route, the backend validates the JWT signature and its claims. If the token is valid, access is granted.


## Security measures
This is a description of security measures implemented in the CI pipeline and how to run them locally.
The pipeline doesn't allow any stage or test to fail for passing. The main branch of the project requires pipeline validated
Some are local python dependencies but the secrets scanning ones are docker based tools so you will need docker.

The local security measures dependencies are segmented from the runtime ones in the ci-requirements.txt. 
We advise to install them in another python venv. You can use the following commands to set it up :

```bash
  python -m venv .ci-venv
```

```bash
  source .ci-venv/bin/activate
```

### Lint
Lint checking is done with flake8. 

Our flake8 rules allow 120 car per lines and ignore python venvs, .git directory and pycache.
```bash
  flake8 .
```

### Tests
Tests are run by pytest and requires a coverage of 85% or more to pass the pipeline.
They use a memory based database for databases tests. 
For some reason we won't disclose the .env must be present to run tests locally ;)

```bash
  pytest --cov=. --cov-report=term-missing --cov-fail-under=85
```

### SCA
For SCA we used pipaudit. 

```bash
  pip-audit -r requirements.txt
```

### SAST 
We use bandit. It is setup to ignore the tests because of the asserts pattern that is seen as a vulnerability.

```bash
  bandit -r .
```

### Secret scanning
Last but not least the secret scanning. This stage ensures that no sensitive information is accidentally committed to the repository. It is composed of two docker based tools :

You must run the following commands outside the project directory so don't forget to :
```bash
  cd ..
```

- `TruffleHog` is used to detect high-entropy strings and potential secrets such as passwords, tokens, or cryptographic keys
in the codebase. It helps identify secrets that may not follow predictable patterns.

    ```bash
      docker run --rm -v "$PWD/devsecops-hash-demo-api:/devsecops-hash-demo-api" trufflesecurity/trufflehog:latest filesystem /devsecops-hash-demo-api/ --include-detectors="all" --exclude-paths="/devsecops-hash-demo-api/.trufflehog"
    ```



- `Gitleaks` is specifically configured to detect API keys, client secrets, and other structured credentials (like our GitLab OAuth2 credentials) 
using a broad set of predefined and custom regex rules. 

    ```bash
      docker run --rm -v "$PWD/devsecops-hash-demo-api:/devsecops-hash-demo-api" ghcr.io/gitleaks/gitleaks:latest dir /devsecops-hash-demo-api/ -v --exit-code 1
    ```


## API Endpoints

Here is the description of the Endpoints this API gives to you.

Caesar Endpoint Added

Every Endpoint has a rate limit of 15 request per minute using slowapi library

* POST /hash
  * Description: This endpoint returns the hashed result of the required algorithm
  * Request Body: {"text": "my secret text", "algorithm": "sha256"}
    * algorithm can be "md5", "sha1", "sha256", "sha512".
  * Example Response (200 OK):
  ```json
  {
    "original_text": "my secret text",
    "algorithm": "sha256",
    "hashed_value": "5b9837714dac5a2d0f4ea4d3328c9073d9f7cacd8990baa0dac9d56de728f63e" 
  }
  ```

* POST /encode_base64
  * Description: This Endpoint returns the encoded version of your text in base64
  * Request Body: {"text": "hello there"}
  * Example Response (200 OK):
  ```json
    {
        "original_text": "hello there",
        "encoded_text": "aGVsbG8gdGhlcmU="
    }
  ```

* POST /decode_base64
  * Description: This Endpoint does the exact inverse of the previous one
  * Request Body: {"text": "aGVsbG8gdGhlcmU="}
  * Example Response (200 OK, successful decoding):
  ```json
    {
        "encoded_text": "aGVsbG8gdGhlcmU=",
        "decoded_text": "hello there",
        "error_message": null
    }
  ```
  * Example Response (200 OK, failed decoding):
  ```json
    {
        "encoded_text": "not base64!!!",
        "decoded_text": null,
        "error_message": "Incorrect padding" 
    }
  ```

* GET /health_crypto_utils
  * Description: Returns the Health check for this API. Doesn't actually do anything in this case.
  * Response: {"status_crypto_utils": "ok"}

* POST /caesar
  * Description: This endpoint performs Caesar cipher encoding or decoding on the provided text.
  * Request Body: {"text": "Hello World", "key": 3, "mode": "encode"}
    * `text`: The string to be processed.
    * `key`: The integer shift to apply.
    * `mode`: Must be either "encode" or "decode".
  * Example Response (200 OK, encode):
  ```json
  {
    "original_text": "Hello World",
    "processed_text": "Khoor Zruog",
    "key": 3,
    "mode": "encode"
  }
  ```
  * Example Response (200 OK, decode):
  ```json
  {
    "original_text": "Khoor Zruog",
    "processed_text": "Hello World",
    "key": 3,
    "mode": "decode"
  }
  ```
  * Example Response (422 Unprocessable Entity, invalid mode):
  ```json
  {
    "detail": "Invalid mode. Must be 'encode' or 'decode'."
  }
  ```

## Database 
The application uses SQLite in combination with the SQLModel ORM to manage data storage. The data model is intentionally simple and consists of two tables:

- User: This table stores information about authenticated users retrieved from GitLab. 
Each entry includes a unique GitLab ID, username, and email address. 
This allows the backend to recognize returning users and associate their activity.


- HashRecord: This table acts as a basic rainbow table. It stores the original input text, 
the chosen hashing algorithm (e.g., MD5, SHA256), and the resulting hash. 
A uniqueness constraint on the combination of input text and algorithm ensures that redundant hash computations are avoided. 
This table can be extended in the future to include additional metadata, such as usage frequency.

All database operations use SQLModel’s ORM layer, which ensures safe, parameterized queries, effectively protecting the system against SQL injection vulnerabilities.


## Project Structure

* main.py: Contains the FastAPI application logic for the hashing/encoding utility.
* auth.py : Contains the authentication logic for oauth2 with gitlab.
* database.py : Contains the database logic (init, models and interactions).
* requirements.txt: Lists the Python dependencies.
* ci-requirement.txt: Lists the dependencies for pipelines : tests, lint, scan and sast (secret are made by docker tools)
* tests/: Contains the automated tests. One test file for each app module + a conftest for environnement variables.
* .env: Contains environnement variables. REQUIRED.
* .env.example: Contains environnement variables model.
* .gitignore : Contains every usual cache file, .venv, and any useful file/directory that should not be pushed to repository
* .gitlab-ci.yml: Defines the GitLab CI/CD pipeline.
* README.md: This file.
* .trufflehog: Contains trufflehog configuration and files to ignore during scans
* .flake8: Contains lint custom rules.
* .bandit: Contains bandit configuration and files to ignore during scans
* __init\__.py : FastAPI requires thoses to recognize a module directory, which was required for the CI Pipeline docker build to correctly execute the tests. If not, it would not find the main.py file and fail the tests

