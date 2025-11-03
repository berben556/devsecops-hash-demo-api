import os
import requests
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.config import Config
import jwt
from jwt.exceptions import InvalidTokenError
import secrets
from database import get_user_by_gitlab_id, create_user, User

router = APIRouter()

# stackage temporaire des state pour contrer les attauqes csrf
oauth_states = set()

config = Config(".env") if os.path.exists(".env") else Config()
GITLAB_CLIENT_ID = config("GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = config("GITLAB_CLIENT_SECRET")
GITLAB_REDIRECT_URI = config("GITLAB_REDIRECT_URI")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = "HS256"

GITLAB_TOKEN_URL = config("GITLAB_TOKEN_URL")
GITLAB_USER_API_URL = config("GITLAB_USER_API_URL")

security = HTTPBearer(auto_error=False)


@router.get("/auth/gitlab/url")
def get_gitlab_oauth_url():
    """
    Génération du lien de connection à gitlab pour le front
    avec les ID et state.
    """
    state = secrets.token_urlsafe(16)
    oauth_states.add(state)

    url = (
        f"https://gitlab.com/oauth/authorize?"
        f"client_id={GITLAB_CLIENT_ID}&"
        f"redirect_uri={GITLAB_REDIRECT_URI}&"
        f"response_type=code&"
        f"state={state}&"
        f"scope=read_user"
    )
    return {"auth_url": url, "state": state}


@router.post("/auth/gitlab/callback")
def gitlab_callback(payload: dict):
    """
    Après connexion à gitlab, le front appel ce endpoint avec le code reçu et le state.
    Le state est vérifié dans le set global.
    Cette fonction échange le code contre uun access_token,
    récupère les infos utilisateur pour vérifier l'existence de ce dernier en bdd ou le créer.
    Enfin un jwt est généré puis renvoyé au front pour le restant des communications.
    """
    code = payload.get("code")
    state = payload.get("state")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    if state not in oauth_states:
        raise HTTPException(status_code=403, detail="Invalid or expired state")
    oauth_states.remove(state)

    token_resp = requests.post(GITLAB_TOKEN_URL, data={
        "client_id": GITLAB_CLIENT_ID,
        "client_secret": GITLAB_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": GITLAB_REDIRECT_URI,
    }, timeout=5)

    if token_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get access token")

    access_token = token_resp.json().get("access_token")

    user_resp = requests.get(GITLAB_USER_API_URL, headers={
        "Authorization": f"Bearer {access_token}"
    }, timeout=5)

    if user_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get user info")

    data = user_resp.json()
    gitlab_id = data["id"]
    username = data["username"]
    email = data["email"]

    user = get_user_by_gitlab_id(gitlab_id)
    if not user:
        user = User(gitlab_id=gitlab_id, username=username, email=email)
        create_user(gitlab_id, username, email)

    jwt_token = generate_jwt_token(user)

    return {"access_token": jwt_token}


def generate_jwt_token(user: User) -> str:
    token_data = {"user_id": user.id, "username": user.username}
    jwt_token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jwt_token


def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)) -> None:
    token = credentials.credentials
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except InvalidTokenError:
        raise HTTPException(status_code=403, detail="Token invalide ou manquant")
