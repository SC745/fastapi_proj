import json
import uuid
import bcrypt
import jwt
import os
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Body, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "/token")
exception_details = {
    "invalid_token": "Неверный токен",
    "expired_token": "Время сессии истекло",
    "invalid_login_password": "Неверный логин или пароль",
    "user_not_found": "Пользователь не найден",
    "user_already_exists": "Пользователь с таким логином уже существует",
    "insufficient_permissions": "Нет прав доступа"
}

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
EXPIRATION_TIME = timedelta(minutes = 1)


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
    
    @staticmethod
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

    @staticmethod
    def get_by_id(id: str, users: list):
        for user in users: 
            if user.id == id: return user
        return None
    
    @staticmethod
    def get_by_login(login: str, users: list):
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


def save_db(users: list):
    users_json = [vars(user) for user in users]
    with open("db.json", "w", encoding = "utf-8") as json_file: json.dump(users_json, json_file, ensure_ascii = False, indent = 4)

def load_db():
    with open("db.json", encoding="utf-8") as json_file: return [User(data) for data in json.loads(json_file.read())]

users = load_db()


app = FastAPI()

@app.post("/")
def get_current_user(token: str = Depends(oauth2_scheme)):
    token = Token.decode(token)
    if not token: raise HTTPException(status_code = 400, detail = exception_details["invalid_token"])
    if token.is_expired(): raise HTTPException(status_code = 400, detail = exception_details["expired_token"])

    user = User.get_by_id(token.user_id, users)
    if not user: raise HTTPException(status_code = 400, detail = exception_details["user_not_found"])

    return user

@app.post("/login")
def auth_user(data = Body()):
    user = User.get_by_login(data["login"], users)
    if not (user and user.is_pw_correct(data["password"])): raise HTTPException(status_code = 400, detail = exception_details["invalid_login_password"])
    token = Token(user.id).encode()
    return {"access_token": token, "token_type": "bearer"}


#Методы register.html (только для admin)

@app.get("/users")
def get_users(current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = exception_details["insufficient_permissions"])
    return users

@app.get("/users/{id}")
def get_user(id, current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = exception_details["insufficient_permissions"])
    user = User.get_by_id(id, users)
    if user == None: raise HTTPException(status_code = 404, detail = exception_details["user_not_found"])
    return user

@app.post("/users")
def create_user(data = Body(), current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = exception_details["insufficient_permissions"])
    if User.get_by_login(data["login"], users): raise HTTPException(status_code = 405, detail = exception_details["user_already_exists"])
    user = User(data)
    users.append(user)
    save_db(users)
    return user

@app.put("/users")
def edit_user(data = Body(), current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = exception_details["insufficient_permissions"])
    user = User.get_by_id(data["id"], users)
    if user == None: raise HTTPException(status_code = 404, detail = exception_details["user_not_found"])
    user.fill_props(data)
    save_db(users)
    return user

@app.delete("/users/{id}")
def delete_user(id, current_user = Depends(get_current_user)):
    if current_user.login != "admin": raise HTTPException(status_code = 403, detail = exception_details["insufficient_permissions"])
    user = User.get_by_id(id, users)
    if user == None: raise HTTPException(status_code = 404, detail = exception_details["user_not_found"])
    users.remove(user)
    save_db(users)
    return user


#Загрузка страниц

@app.get("/")
def root_page():
    return FileResponse("pages/root.html")

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


if __name__ == "__main__":
    uvicorn.run("app:app", host="localhost", port=8000, reload=True)