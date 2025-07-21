import json
import uuid
import bcrypt
import jwt
from fastapi import FastAPI, Depends, Body, status, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
EXPIRATION_TIME = timedelta(seconds = 30)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "/token")

with open("db.json", encoding="utf-8") as json_file: users = json.loads(json_file.read())


def find_user(value, key):
    for user in users: 
        if user[key] == value: return user
    return None

def hash_password(password: str):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(user_password: str, hashed_password: str):
    return bcrypt.checkpw(user_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_token(user_id: str):
    data = {}
    data["user_id"] = user_id
    data["expiration"] = (datetime.utcnow() + EXPIRATION_TIME).isoformat()

    return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)

def verify_token(token: str):
    try: return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError: return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    data = verify_token(token)
    if not data: raise HTTPException(status_code = 400, detail = "Invalid token")
    if datetime.fromisoformat(data["expiration"]) < datetime.utcnow(): raise HTTPException(status_code = 400, detail = "Expired token")
    user = find_user(data["user_id"], "id")
    if not user: raise HTTPException(status_code = 400, detail = "User not found")
    return user

def is_admin(current_user = Depends(get_current_user)):
    if current_user["login"] == "admin": return current_user
    raise HTTPException(status_code=403, detail="Insufficient permissions")


app = FastAPI()

@app.get("/login")
def login_page():
    return FileResponse("pages/login.html")


@app.get("/register")
def register_page():
    return FileResponse("pages/register.html")

@app.get("/home")
def register_page():
    return FileResponse("pages/home.html")

@app.post("/home")
def home(current_user = Depends(get_current_user)):
    return current_user


@app.post("/login")
def authentificate_user(data = Body()):
    user = find_user(data["login"], "login")
    if not user: raise HTTPException(status_code = 400, detail = "Incorrect username or password")
    password_correct = verify_password(data["password"], user["hashed_password"])
    if not password_correct: raise HTTPException(status_code = 400, detail = "Incorrect username or password")
    token = create_token(user["id"])
    return {"access_token": token, "token_type": "bearer"}





@app.get("/users")
def get_users(admin = Depends(is_admin)):
    return users

@app.get("/users/{id}")
def get_user(id, admin = Depends(is_admin)):
    user = find_user(id, "id")
    if user == None: return JSONResponse(status_code = status.HTTP_404_NOT_FOUND, content = {"message": "Пользователь не найден"})
    return user

@app.post("/users")
def create_user(data  = Body(), admin = Depends(is_admin)):
    user = {}
    user["id"] = str(uuid.uuid4())
    for key in data:
        if key != "password": user[key] = data[key]
        else: user["hashed_password"] = hash_password(data["password"])
    users.append(user)
    with open("db.json", "w", encoding = "utf-8") as json_file: json.dump(users, json_file, ensure_ascii = False, indent = 4)
    return user

@app.put("/users")
def edit_user(data  = Body(), admin = Depends(is_admin)):
    user = find_user(data["id"], "id")
    if user == None: return JSONResponse(status_code = status.HTTP_404_NOT_FOUND, content = {"message": "Пользователь не найден"})
    for key in data:
        if key != "password": user[key] = data[key]
        else: user["hashed_password"] = hash_password(data["password"])
    return user

@app.delete("/users/{id}")
def delete_user(id, admin = Depends(is_admin)):
    user = find_user(id, "id")
    if user == None: return JSONResponse(status_code = status.HTTP_404_NOT_FOUND, content = {"message": "Пользователь не найден"})
    users.remove(user)
    with open("db.json", "w", encoding = "utf-8") as json_file: json.dump(users, json_file, ensure_ascii = False, indent = 4)
    return user