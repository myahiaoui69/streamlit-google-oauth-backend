import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth
from jose import jwt
from datetime import datetime, timedelta
from starlette.middleware.sessions import SessionMiddleware  # <-- ajouté


app = FastAPI()

# Middleware des sessions (nécessaire pour Authlib)
app.add_middleware(SessionMiddleware, secret_key=os.environ["JWT_SECRET"])


# Chargés depuis Railway (Variables d’environnement)
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
JWT_SECRET = os.environ["JWT_SECRET"]

oauth = OAuth()

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

@app.get("/")
def root():
    return {"status": "OAuth backend running"}

@app.get("/login")
async def login(request: Request):
    # Redirige l'utilisateur vers Google
    redirect_uri = request.url_for("auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/callback")
async def auth_callback(request: Request):
    # Google renvoie ici avec un "code"
    token = await oauth.google.authorize_access_token(request)
    user = token["userinfo"]

    user_id = user["sub"]  # ID Google unique, stable, mondial
    email = user["email"]

    # On crée un JWT signé pour Streamlit
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=12)
    }

    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # On renvoie vers Streamlit avec le token
    streamlit_url = os.environ["STREAMLIT_APP_URL"]
    return RedirectResponse(f"{streamlit_url}?token={jwt_token}")

@app.get("/me")
def me(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except:
        return JSONResponse({"error": "Invalid token"}, status_code=401)
