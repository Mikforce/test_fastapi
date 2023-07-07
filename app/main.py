from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
import sqlite3
import uvicorn
import requests



app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    id: int
    text: str
    owner: str

def get_database_connection():
    conn = sqlite3.connect("database.db")
    return conn

def get_database_cursor():
    conn = get_database_connection()
    cursor = conn.cursor()
    return cursor

def create_tables_if_not_exist():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT,
            owner TEXT
        )
        """
    )
    conn.commit()

def get_user(username: str):
    conn = get_database_connection()
    cursor = conn.cursor()
    query = "SELECT id, username, password FROM users WHERE username = ?"
    user = cursor.execute(query, (username,)).fetchone()
    return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user[2]):
        return False
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    user = get_user(username=token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return user


# Добавление данных пользователя с использованием Clearbit


def enrich_user_data(email: str):
    clearbit_api_key = "YOUR_CLEARBIT_API_KEY"
    url = f"https://person.clearbit.com/v2/combined/find?email={email}"
    headers = {"Authorization": f"Bearer {clearbit_api_key}"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Clearbit API request failed: {e}")
        return None

# Проверка наличия электронной почты с использованием Email Hunter

def verify_email(email: str):
    email_hunter_api_key = "YOUR_EMAILHUNTER_API_KEY"
    url = f"https://api.emailhunter.co/v2/email-verifier?email={email}"
    headers = {"Authorization": f"Bearer {email_hunter_api_key}"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["result"] == "deliverable"
    except requests.exceptions.RequestException as e:
        print(f"Email Hunter API request failed: {e}")
        return False

templates = Jinja2Templates(directory="templates")



@app.post("/register")
def register(user: User):
    if not verify_email(user.username):
        raise HTTPException(status_code=400, detail="Invalid email address")

    user_data = enrich_user_data(user.username)
    if user_data is not None:

        print(user_data)

    conn = get_database_connection()
    query = "INSERT INTO users (username, password) VALUES (?, ?)"
    hashed_password = get_password_hash(user.password)
    cursor = conn.cursor()
    cursor.execute(query, (user.username, hashed_password))
    conn.commit()

    return {"message": "User registered successfully"}


@app.post("/token")
def login(user: User):
    authenticated_user = authenticate_user(user.username, user.password)
    if not authenticated_user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"access_token": authenticated_user[1], "token_type": "bearer"}

@app.post("/create_message")
def create_message(message: Message, current_user: User = Depends(get_current_user)):
    conn = get_database_connection()
    query = "INSERT INTO messages (text, owner) VALUES (?, ?)"
    cursor = conn.cursor()
    cursor.execute(query, (message.text, current_user[1]))
    conn.commit()

    return {"message": "Message created successfully"}

@app.get("/messages")
def get_messages():
    conn = get_database_connection()
    query = "SELECT id, text, owner FROM messages"
    cursor = conn.cursor()
    result = cursor.execute(query).fetchall()
    messages = []
    for row in result:
        message = {"id": row[0], "text": row[1], "owner": row[2]}
        messages.append(message)

    return {"messages": messages}

@app.delete("/messages/{message_id}")
def delete_message(message_id: int, current_user: User = Depends(get_current_user)):
    conn = get_database_connection()
    query = "DELETE FROM messages WHERE id = ? AND owner = ?"
    cursor = conn.cursor()
    cursor.execute(query, (message_id, current_user[1]))
    conn.commit()
    return {"message": "Message deleted successfully"}


@app.post("/messages/{message_id}/like")
def like_message(message_id: int, current_user: User = Depends(get_current_user)):
    conn = get_database_connection()
    query = "SELECT owner FROM messages WHERE id = ?"
    cursor = conn.cursor()
    result = cursor.execute(query, (message_id,)).fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Message not found")
    owner = result[0]
    if current_user["username"] == owner:
        raise HTTPException(status_code=400, detail="You cannot like your own message")

    # Проверяем, есть ли уже лайк от текущего пользователя для данного сообщения
    like_query = "SELECT count(*) FROM likes WHERE user_id = ? AND message_id = ?"
    like_count = cursor.execute(like_query, (current_user["id"], message_id)).fetchone()[0]
    if like_count > 0:
        raise HTTPException(status_code=400, detail="You have already liked this message")

    # Добавляем запись о лайке в базу данных
    insert_like_query = "INSERT INTO likes (user_id, message_id) VALUES (?, ?)"
    cursor.execute(insert_like_query, (current_user["id"], message_id))
    conn.commit()

    return {"message": "Like added successfully"}


@app.delete("/messages/{message_id}/like")
def dislike_message(message_id: int, current_user: User = Depends(get_current_user)):
    conn = get_database_connection()
    query = "SELECT owner FROM messages WHERE id = ?"
    cursor = conn.cursor()
    result = cursor.execute(query, (message_id,)).fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Message not found")
    owner = result[0]
    if current_user["username"] == owner:
        raise HTTPException(status_code=400, detail="You cannot dislike your own message")

    # Проверяем, есть ли лайк от текущего пользователя для данного сообщения
    like_query = "SELECT count(*) FROM likes WHERE user_id = ? AND message_id = ?"
    like_count = cursor.execute(like_query, (current_user["id"], message_id)).fetchone()[0]
    if like_count == 0:
        raise HTTPException(status_code=400, detail="You have not liked this message")

    # Удаляем запись о лайке из базы данных
    delete_like_query = "DELETE FROM likes WHERE user_id = ? AND message_id = ?"
    cursor.execute(delete_like_query, (current_user["id"], message_id))
    conn.commit()

    return {"message": "Dislike added successfully"}


@app.get("/docs")
async def get_docs():
    return {
        "Swagger UI": "/docs",
        "ReDoc": "/redoc"
    }
@app.get("/openapi.json")
async def get_openapi():
    return app.openapi()

@app.get("/redoc")
async def get_redoc():
    return {"msg": "You are viewing the ReDoc documentation."}


if __name__ == "__main__":
    create_tables_if_not_exist()
    uvicorn.run(app, port=8080)


