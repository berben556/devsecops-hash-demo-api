import hashlib
import base64
from contextlib import asynccontextmanager
from enum import Enum
from fastapi import FastAPI, Body, status, Request, HTTPException, Depends
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from auth import router as auth_router, verify_jwt
from database import init_db, log_hash_request

# Rate Limiter Configuration
RATE_LIMIT = "500/minute"  # Global rate limit for all endpoints
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # initialisation de la base de donnée
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restreindre en prod
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Add rate limit exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router)


# --- Enums and Pydantic Models ---


class HashAlgorithm(str, Enum):
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    sha512 = "sha512"


class HashRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text to be hashed.")
    algorithm: HashAlgorithm = Field(..., description="Hashing algorithm to use.")


class HashResponse(BaseModel):
    original_text: str
    algorithm: HashAlgorithm
    hashed_value: str


class Base64TextRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text for Base64 operation.")


class Base64EncodeResponse(BaseModel):
    original_text: str
    encoded_text: str


class Base64DecodeResponse(BaseModel):
    encoded_text: str
    decoded_text: str | None  # Can be None if decoding fails
    error_message: str | None = None  # For potential decoding errors


class CaesarRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text for Caesar cipher operation.")
    key: int = Field(..., description="Key (shift) for Caesar cipher.")
    mode: str = Field(..., description="Mode: 'encode' or 'decode'.")


class CaesarResponse(BaseModel):
    original_text: str
    processed_text: str
    key: int
    mode: str

# --- Business Logic ---


def perform_hash(text_to_hash: str, algorithm: HashAlgorithm) -> str:
    """
    Performs hashing on the given text using the specified algorithm.
    STUDENTS TO COMPLETE THIS FUNCTION.
    """
    # Get the text_to_hash and encode it to bytes (e.g., UTF-8).
    text_bytes = text_to_hash.encode('utf-8')

    # Create a hash object based on the `algorithm` string.
    match algorithm:
        case "md5":
            hasher = hashlib.new('md5', usedforsecurity=False)
        case "sha1":
            hasher = hashlib.new('sha1', usedforsecurity=False)
        case "sha256":
            hasher = hashlib.new('sha256', usedforsecurity=False)
        case "sha512":
            hasher = hashlib.new('sha512', usedforsecurity=False)
        case _:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    # Update the hasher with the `text_bytes`.
    hasher.update(text_bytes)

    # Get the hexadecimal representation of the hash.
    hashed_hex = hasher.hexdigest()

    return hashed_hex


def encode_to_base64(text_to_encode: str) -> str:
    """
    Encodes the given text to Base64.
    STUDENTS TO COMPLETE THIS FUNCTION.
    """
    # Encode the `text_to_encode` to bytes (e.g., UTF-8).
    text_bytes = text_to_encode.encode('utf-8')

    # Use `base64.b64encode()` on the `text_bytes`.
    base64_bytes = base64.b64encode(text_bytes)

    # Decode the `base64_bytes` result back to a string (e.g., UTF-8).
    encoded_string = base64_bytes.decode('utf-8')

    return encoded_string


def decode_from_base64(encoded_text: str) -> tuple[str | None, str | None]:
    """
    Decodes the given Base64 encoded text.
    Returns a tuple: (decoded_string, error_message).
    If decoding is successful, error_message is None.
    If decoding fails, decoded_string is None.
    STUDENTS TO COMPLETE THIS FUNCTION.
    """
    # Try to encode the `encoded_text` to bytes (e.g., UTF-8),
    #          then use `base64.b64decode()` on these bytes.
    #          The result of b64decode will be bytes. Decode these bytes back
    #          to a string (e.g., UTF-8).
    #          Wrap this in a try-except block to catch `base64.binascii.Error`
    #          (or general Exception)
    #          which can occur if the input is not valid Base64.
    try:
        padding_needed = len(encoded_text) % 4
        if padding_needed:
            encoded_text += '=' * (4 - padding_needed)

        base64_bytes_to_decode = encoded_text.encode('utf-8')
        decoded_bytes = base64.b64decode(base64_bytes_to_decode)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string, None
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        return None, str(e)


def perform_caesar_cipher(text: str, key: int, mode: str) -> str:
    """
    Performs Caesar cipher encoding or decoding on the given text.
    """
    result = []
    if mode == "decode":
        key = -key

    for char in text:
        if 'a' <= char <= 'z':
            shifted_char = chr(((ord(char) - ord('a') + key) % 26) + ord('a'))
            result.append(shifted_char)
        elif 'A' <= char <= 'Z':
            shifted_char = chr(((ord(char) - ord('A') + key) % 26) + ord('A'))
            result.append(shifted_char)
        else:
            result.append(char)
    return "".join(result)


# --- API Endpoints ---
@app.post("/hash", response_model=HashResponse, status_code=status.HTTP_200_OK,
          dependencies=[Depends(verify_jwt)])
@limiter.limit("15/minute")  # 15 Requests per minute
async def hash_text_endpoint(request: Request,
                             payload: HashRequest = Body(...)):
    # Call `perform_hash` with `payload.text` and `payload.algorithm`.
    #    Construct and return a `HashResponse`.

    hashed_value = perform_hash(payload.text, payload.algorithm)

    # Save the hash into the rainbow table
    log_hash_request(payload.algorithm, payload.text, hashed_value)

    return HashResponse(
        original_text=payload.text,
        algorithm=payload.algorithm,
        hashed_value=hashed_value
    )


@app.post("/encode_base64", response_model=Base64EncodeResponse,
          status_code=status.HTTP_200_OK, dependencies=[Depends(verify_jwt)])
@limiter.limit("15/minute")  # 15 requests per minute
async def encode_base64_endpoint(request: Request,
                                 payload: Base64TextRequest = Body(...)):
    # Call `encode_to_base64` with `payload.text`.
    #       Construct and return a `Base64EncodeResponse`.

    encoded_text = encode_to_base64(payload.text)
    return Base64EncodeResponse(
        original_text=payload.text,
        encoded_text=encoded_text
    )


@app.post("/decode_base64", response_model=Base64DecodeResponse,
          status_code=status.HTTP_200_OK, dependencies=[Depends(verify_jwt)])
@limiter.limit("15/minute")  # 15 requests per minute
async def decode_base64_endpoint(request: Request,
                                 payload: Base64TextRequest = Body(...)):
    # Call `decode_from_base64` with `payload.text`.
    #   If decoding is successful (no error message),
    #   construct `Base64DecodeResponse`.
    #   If decoding fails, you might want to raise an
    #   HTTPException(status_code=400)
    #   or return a 200 OK with the error message in the response body as
    #   defined by Base64DecodeResponse.
    #   For this TP, returning 200 OK with an error in the body is simpler.

    decoded_text, error_msg = decode_from_base64(payload.text)
    if error_msg:
        return Base64DecodeResponse(
            encoded_text=payload.text,
            decoded_text=None,
            error_message=f"Base64 decoding error: {error_msg}")

    return Base64DecodeResponse(
        encoded_text=payload.text,
        decoded_text=decoded_text,
        error_message=None
    )


@app.get("/health_crypto_utils")
@limiter.limit("15/minute")  # 15 requests per minute
async def health_check_crypto_utils(request: Request):
    return {"status_crypto_utils": "ok"}


@app.post("/caesar", response_model=CaesarResponse,
          status_code=status.HTTP_200_OK, dependencies=[Depends(verify_jwt)])
@limiter.limit("15/minute")  # 15 requests per minute
async def caesar_cipher_endpoint(request: Request,
                                 payload: CaesarRequest = Body(...)):
    if payload.mode not in ["encode", "decode"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid mode. Must be 'encode' or 'decode'."
        )

    processed_text = perform_caesar_cipher(payload.text,
                                           payload.key,
                                           payload.mode)
    return CaesarResponse(
        original_text=payload.text,
        processed_text=processed_text,
        key=payload.key,
        mode=payload.mode
    )

# For running with `python main.py`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
