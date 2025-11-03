# Hashing and Encoding Utility API

## Description

This project is a school project aiming to build a hashing utility with all the developping, testing and production pipeline required for secured projects. 
It implements :
- CI pipeline composed of lint verification, unit tests with 85% coverage limitation, SCA, SAST and secret checking.
- Oauth2 and jwt tokens for authentication *(Using Gitlab Oauth2 because the project was originaly on gitlab)*.

I added a Rate Limiter using slowapi library and a new endpoint for caesar encoding and decoding.

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
- Gitlab Oauth2 — Secret scanning tool for Git repositories.

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
  docker build -t devsecop .
```

```bash
  docker run -p 8000:8000 devsecop:latest
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
      docker run --rm -v "$PWD/hash-encoder-back-end:/hash-encoder-back-end" trufflesecurity/trufflehog:latest filesystem /hash-encoder-back-end/ --include-detectors="all" --exclude-paths="/hash-encoder-back-end/.trufflehog"
    ```



- `Gitleaks` is specifically configured to detect API keys, client secrets, and other structured credentials (like our GitLab OAuth2 credentials) 
using a broad set of predefined and custom regex rules. 

    ```bash
      docker run --rm -v "$PWD/hash-encoder-back-end:/hash-encoder-back-end" ghcr.io/gitleaks/gitleaks:latest dir /hash-encoder-back-end/ -v --exit-code 1
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

