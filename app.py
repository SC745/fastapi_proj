import json
import uuid
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Body, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "/token")
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
EXPIRATION_TIME = timedelta(minutes = 5)


class Token:
    def __init__(self, user_id: str, expiration: str = None):
        self.__user_id = user_id
        if isinstance(expiration, str): self.__expiration = datetime.fromisoformat(expiration)
        else: self.__expiration = datetime.utcnow() + EXPIRATION_TIME
    
    @property
    def user_id(self):
        return self.__user_id

    @property
    def expiration(self):
        return self.__expiration
    
    def encode(self):
        data = {}
        data["user_id"] = self.__user_id
        data["expiration"] = (self.__expiration).isoformat()
        return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)
    
    def decode(token):
        try: 
            data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return Token(data["user_id"], data["expiration"])
        except jwt.PyJWTError: return None

    def is_expired(self):
        return self.__expiration < datetime.utcnow() 

class User:
    def __init__(self, data: dict):
        self.id = data["id"] if "id" in data else str(uuid.uuid4())
        self.fill_props(data)

    def is_pw_correct(self, password: str):
        return bcrypt.checkpw(password.encode("utf-8"), self.hashed_password.encode("utf-8"))

    def get_by_id(id: str):
        for user in users: 
            if user.id == id: return user
        return None
    
    def get_by_login(login: str):
        for user in users: 
            if user.login == login: return user
        return None
    
    def fill_props(self, data: dict):
        self.name = data["name"]
        self.login = data["login"]
        if "password" in data: self.hashed_password = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        elif "hashed_password" in data: self.hashed_password = data["hashed_password"]
        self.salary = data["salary"]
        self.promdate = data["promdate"]


def save_db(users):
    users_json = [vars(user) for user in users]
    with open("db.json", "w", encoding = "utf-8") as json_file: json.dump(users_json, json_file, ensure_ascii = False, indent = 4)

def load_db():
    with open("db.json", encoding="utf-8") as json_file: return [User(data) for data in json.loads(json_file.read())]


users = load_db()

app = FastAPI()

@app.post("/home")
def get_current_user(token: str = Depends(oauth2_scheme)):
    token = Token.decode(token)
    if not token: raise HTTPException(status_code = 400, detail = "Invalid token")
    if token.is_expired(): raise HTTPException(status_code = 400, detail = "Expired token")

    user = User.get_by_id(token.user_id)
    if not user: raise HTTPException(status_code = 400, detail = "User not found")

    return user

@app.post("/login")
def auth_user(data = Body()):
    user = User.get_by_login(data["login"])
    if not (user and user.is_pw_correct(data["password"])): raise HTTPException(status_code = 400, detail = "Incorrect username or password")
    token = Token(user.id).encode()
    return {"access_token": token, "token_type": "bearer"}


#Методы register.html (только для admin)

@app.get("/users")
def get_users(current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = "Insufficient permissions")
    return users

@app.get("/users/{id}")
def get_user(id, current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = "Insufficient permissions")
    user = User.get_by_id(id)
    if user == None: raise HTTPException(status_code = 404, detail = "User not found")
    return user

@app.post("/users")
def create_user(data = Body(), current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = "Insufficient permissions")
    if User.get_by_login(data["login"]): raise HTTPException(status_code = 405, detail = "User with this login already exisrs")
    user = User(data)
    users.append(user)
    save_db(users)
    return user

@app.put("/users")
def edit_user(data = Body(), current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = "Insufficient permissions")
    user = User.get_by_id(data["id"])
    if user == None: raise HTTPException(status_code = 404, detail = "User not found")
    user.fill_props(data)
    save_db(users)
    return user

@app.delete("/users/{id}")
def delete_user(id, current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = "Insufficient permissions")
    user = User.get_by_id(id)
    if user == None: raise HTTPException(status_code = 404, detail = "User not found")
    users.remove(user)
    save_db(users)
    return user


#Загрузка страниц

@app.get("/login")
def login_page():
    return FileResponse("pages/login.html")

@app.get("/logout")
def logout_page():
    return FileResponse("pages/logout.html")

@app.get("/register")
def register_page():
    return FileResponse("pages/register.html")

@app.get("/home")
def register_page():
    return FileResponse("pages/home.html")