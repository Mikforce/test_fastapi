import uvicorn

from pydantic import BaseModel

import sqlite3
from sqlite3 import Error
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional
import httpx
from pydantic import EmailStr


app = FastAPI()

# Define some constants for JWT authentication
SECRET_KEY = "your-secret-key"  # Change this to your own secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Create a password context for validating and hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SQLite database connection
conn = None


def create_connection():
    global conn
    try:
        conn = sqlite3.connect("social_network.db")
        print(f"SQLite version: {sqlite3.version}")
    except Error as e:
        print(e)


def close_connection():
    if conn:
        conn.close()


def execute_query(query, params=None):
    cursor = conn.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    conn.commit()
    return cursor


def create_table():
    queries = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            hashed_password TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (author_id) REFERENCES users (id)
        );
        """
    ]

    for query in queries:
        execute_query(query)




def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str):
    query = "SELECT * FROM users WHERE username = ?"
    result = execute_query(query, (username,))
    user_data = result.fetchone()
    if user_data:
        user = {
            "id": user_data[0],
            "username": user_data[1],
            "full_name": user_data[2],
            "email": user_data[3],
            "hashed_password": user_data[4],
        }
        return user


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: int):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.on_event("startup")
async def startup_event():
    create_connection()
    create_table()


@app.on_event("shutdown")
async def shutdown_event():
    close_connection()


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
async def read_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


class PostCreateRequest(BaseModel):
    title: str
    content: str


class PostUpdateRequest(BaseModel):
    title: Optional[str]
    content: Optional[str]


@app.get("/posts", response_model=List[PostCreateRequest])
async def get_posts():
    query = "SELECT title, content FROM posts"
    result = execute_query(query)
    posts = []
    for post_data in result.fetchall():
        post = {"title": post_data[0], "content": post_data[1]}
        posts.append(post)
    return posts

@app.post("/posts")
async def create_post(post: PostCreateRequest, current_user: dict = Depends(read_current_user)):
    query = "INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)"
    params = (current_user["id"], post.title, post.content)
    execute_query(query, params)
    return post.dict()


@app.put("/posts/{post_id}")
async def update_post(post_id: int, post: PostUpdateRequest, current_user: dict = Depends(read_current_user)):
    query = "SELECT * FROM posts WHERE id = ?"
    result = execute_query(query, (post_id,))
    post_data = result.fetchone()
    if not post_data:
        raise HTTPException(status_code=404, detail="Post not found")

    author_id = post_data[1]
    if author_id != current_user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    updated_fields = {k: v for k, v in post.dict().items() if v is not None}
    if not updated_fields:
        return post.dict()

    set_statements = ", ".join([f"{key} = ?" for key in updated_fields.keys()])
    params = tuple(updated_fields.values()) + (post_id,)
    query = f"UPDATE posts SET {set_statements} WHERE id = ?"
    execute_query(query, params)

    updated_post = post.dict()
    return updated_post


@app.delete("/posts/{post_id}")
async def delete_post(post_id: int, current_user: dict = Depends(read_current_user)):
    query = "SELECT * FROM posts WHERE id = ?"
    result = execute_query(query, (post_id,))
    post_data = result.fetchone()
    if not post_data:
        raise HTTPException(status_code=404, detail="Post not found")

    author_id = post_data[1]
    if author_id != current_user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    query = "DELETE FROM posts WHERE id = ?"
    execute_query(query, (post_id,))
    return {"message": "Post deleted successfully."}


class LikeRequest(BaseModel):
    post_id: int


@app.post("/posts/{post_id}/like")
async def like_post(post_id: int, like_request: LikeRequest, current_user: dict = Depends(read_current_user)):
    query = "SELECT * FROM posts WHERE id = ?"
    result = execute_query(query, (post_id,))
    post_data = result.fetchone()
    if not post_data:
        raise HTTPException(status_code=404, detail="Post not found")

    liked_post_author_id = post_data[1]
    if liked_post_author_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot like your own post")

    query = "INSERT INTO likes (user_id, post_id) VALUES (?, ?)"
    params = (current_user["id"], post_id)
    execute_query(query, params)

    return {"message": "Post liked successfully."}


@app.post("/posts/{post_id}/dislike")
async def dislike_post(post_id: int, like_request: LikeRequest, current_user: dict = Depends(read_current_user)):
    query = "SELECT * FROM posts WHERE id = ?"
    result = execute_query(query, (post_id,))
    post_data = result.fetchone()
    if not post_data:
        raise HTTPException(status_code=404, detail="Post not found")

    disliked_post_author_id = post_data[1]
    if disliked_post_author_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot dislike your own post")

    query = "DELETE FROM likes WHERE user_id = ? AND post_id = ?"
    params = (current_user["id"], post_id)
    execute_query(query, params)

    return {"message": "Post disliked successfully."}

# Swagger UI and ReDoc documentation
@app.get("/docs")
async def get_docs():
    return {"msg": "You are viewing the Swagger UI documentation. Proceed to /redoc for ReDoc documentation."}


@app.get("/redoc")
async def get_redoc():
    return {"msg": "You are viewing the ReDoc documentation."}


if __name__ == "__main__":
    uvicorn.run(app, port=8000)