import pytest
from fastapi.testclient import TestClient
from fastapi import status
import database
from auth import verify_jwt


def override_verify_jwt():
    return None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(database, "log_hash_request", lambda *args, **kwargs: None)

    from main import app
    app.dependency_overrides[verify_jwt] = override_verify_jwt
    return TestClient(app)


def test_health_check_crypto_utils(client):
    response = client.get("/health_crypto_utils")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status_crypto_utils": "ok"}


# --- Hashing Tests ---
def test_hash_sha256_success(client):
    text_to_hash = "hello world"
    # Known SHA256 hash for "hello world"
    expected_hash = (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )

    response = client.post("/hash", json={"text": text_to_hash, "algorithm": "sha256"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_hash
    assert data["algorithm"] == "sha256"
    assert data["hashed_value"] == expected_hash


def test_hash_md5_success(client):
    text_to_hash = "FastAPI ROCKS"
    # Known MD5 hash for "FastAPI ROCKS"
    expected_hash = "8334dc350a1fb34349a0d64dfd670145".lower()
    # hashlib often returns lowercase

    response = client.post("/hash", json={"text": text_to_hash, "algorithm": "md5"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Complete assertions for MD5 hashing.
    assert data["hashed_value"] == expected_hash


def test_hash_invalid_algorithm(client):
    # Pydantic's Enum validation for HashAlgorithm should handle this.
    response = client.post("/hash", json={"text": "test", "algorithm": "unknown_algo"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

# --- Base64 Encoding Tests ---


def test_encode_base64_success(client):
    text_to_encode = "Cybersecurity is fun!"
    # Known Base64 encoding for "Cybersecurity is fun!"
    expected_encoded = "Q3liZXJzZWN1cml0eSBpcyBmdW4h"

    response = client.post("/encode_base64", json={"text": text_to_encode})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_encode
    assert data["encoded_text"] == expected_encoded

# --- Base64 Decoding Tests ---


def test_decode_base64_success(client):
    encoded_text = "SGVsbG8gV29ybGQh"  # "Hello World!"
    expected_decoded = "Hello World!"

    response = client.post("/decode_base64", json={"text": encoded_text})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["encoded_text"] == encoded_text
    assert data["decoded_text"] == expected_decoded
    assert data["error_message"] is None


def test_decode_base64_invalid_input(client):
    invalid_encoded_text = "This is not valid Base64!!!"

    response = client.post("/decode_base64",
                           json={"text": invalid_encoded_text})
    assert response.status_code == status.HTTP_200_OK
    # As per current main.py logic
    data = response.json()

    assert data["decoded_text"] is None
    assert data["error_message"] is not None
    assert "decoding error" in data["error_message"].lower()

# --- Input Validation Tests (Pydantic) ---


def test_hash_missing_text(client):
    response = client.post("/hash", json={"algorithm": "sha256"})
    # Missing "text"
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_encode_base64_empty_text(client):
    # Pydantic model Base64TextRequest has min_length=1 for text field
    response = client.post("/encode_base64", json={"text": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# --- Bonus Tests for SHA1 and SHA512 Hashing ---


def test_hash_sha1_success(client):
    text_to_hash = "secure password"
    # Known SHA1 hash for "secure password"
    expected_hash = (
        "00097e239bacc4d0bc0306d92e956c76d2208e4c"
    )

    response = client.post("/hash", json={"text": text_to_hash,
                                          "algorithm": "sha1"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_hash
    assert data["algorithm"] == "sha1"
    assert data["hashed_value"] == expected_hash


def test_hash_sha512_success(client):
    text_to_hash = "cryptography"
    # Known SHA512 hash for "cryptography"
    expected_hash = (
        "cd700ec1a9830c273b5c4f0de34829a0a427294e41c3dfc243591a3caf68927ab84"
        "be7a91cd16e34275f66b7cd76a53c4bb117215a4b18074303197e6594347b"
    )

    response = client.post("/hash", json={"text": text_to_hash,
                                          "algorithm": "sha512"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_hash
    assert data["algorithm"] == "sha512"
    assert data["hashed_value"] == expected_hash


# --- Bonus Tests for Base64 Edge Cases ---
def test_base64_padding_encode(client):
    # Test different padding scenarios
    # 1 character padding (2 bytes, resulting in '==')
    text_one_pad = "a"
    expected_one_pad = "YQ=="

    response = client.post("/encode_base64", json={"text": text_one_pad})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["encoded_text"] == expected_one_pad

    # 2 character padding (1 byte, resulting in '=')
    text_two_pad = "ab"
    expected_two_pad = "YWI="

    response = client.post("/encode_base64", json={"text": text_two_pad})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["encoded_text"] == expected_two_pad

    # No padding needed (3 bytes)
    text_no_pad = "abc"
    expected_no_pad = "YWJj"

    response = client.post("/encode_base64", json={"text": text_no_pad})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["encoded_text"] == expected_no_pad


def test_base64_special_characters_encode(client):
    # Test encoding special characters
    text_with_special = "Hello, World! äöü 你好"
    expected_encoded = "SGVsbG8sIFdvcmxkISDDpMO2w7wg5L2g5aW9"

    response = client.post("/encode_base64", json={"text": text_with_special})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["encoded_text"] == expected_encoded


def test_base64_padding_decode(client):
    # Test decoding with different padding scenarios
    encoded_one_pad = "YQ=="  # "a"
    expected_one_pad = "a"

    response = client.post("/decode_base64", json={"text": encoded_one_pad})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["decoded_text"] == expected_one_pad

    # Test missing padding (should still work with proper Base64 decoders)
    encoded_missing_pad = "YWI"  # Should be "YWI="
    expected_missing_pad = "ab"

    response = client.post("/decode_base64",
                           json={"text": encoded_missing_pad})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["decoded_text"] == expected_missing_pad


# --- Caesar Cipher Tests ---

def test_caesar_encode_success(client):
    text_to_encode = "Hello World"
    key = 3
    expected_text = "Khoor Zruog"

    response = client.post("/caesar", json={"text": text_to_encode,
                                            "key": key,
                                            "mode": "encode"
                                            })
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_encode
    assert data["processed_text"] == expected_text
    assert data["key"] == key
    assert data["mode"] == "encode"


def test_caesar_decode_success(client):
    text_to_decode = "Khoor Zruog"
    key = 3
    expected_text = "Hello World"

    response = client.post("/caesar", json={"text": text_to_decode,
                                            "key": key,
                                            "mode": "decode"
                                            })
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["original_text"] == text_to_decode
    assert data["processed_text"] == expected_text
    assert data["key"] == key
    assert data["mode"] == "decode"


def test_caesar_non_alphabetic_chars(client):
    text_to_process = "Hello, World! 123"
    key = 5
    expected_encoded = "Mjqqt, Btwqi! 123"

    # Test encode
    response_encode = client.post("/caesar", json={
        "text": text_to_process,
        "key": key,
        "mode": "encode"
    })
    assert response_encode.status_code == status.HTTP_200_OK
    data_encode = response_encode.json()
    assert data_encode["processed_text"] == expected_encoded

    # Test decode
    response_decode = client.post("/caesar", json={
        "text": expected_encoded,
        "key": key,
        "mode": "decode"
    })
    assert response_decode.status_code == status.HTTP_200_OK
    data_decode = response_decode.json()
    assert data_decode["processed_text"] == text_to_process


def test_caesar_large_key(client):
    text_to_encode = "abc"
    key = 29
    expected_text = "def"

    response = client.post("/caesar", json={
        "text": text_to_encode,
        "key": key,
        "mode": "encode"
    })
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["processed_text"] == expected_text

    response_decode = client.post("/caesar", json={
        "text": expected_text,
        "key": key,
        "mode": "decode"
    })
    assert response_decode.status_code == status.HTTP_200_OK
    data_decode = response_decode.json()
    assert data_decode["processed_text"] == text_to_encode


def test_caesar_invalid_mode(client):
    response = client.post("/caesar", json={
        "text": "test",
        "key": 3,
        "mode": "invalid_mode"
    })
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
