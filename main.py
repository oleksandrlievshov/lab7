from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional, List
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os

app = FastAPI()

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
client = AsyncIOMotorClient(MONGO_URI)
db = client["library"]
books_collection = db["books"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_user = {
    "username": "admin",
    "hashed_password": pwd_context.hash("secret")
}

# Pydantic моделі
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

class Book(BaseModel):
    id: Optional[str]
    title: str
    author: str

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def authenticate_user(username: str, password: str):
    if username != fake_user["username"]:
        return False
    if not verify_password(password, fake_user["hashed_password"]):
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": form_data.username})
    refresh_token = create_refresh_token(data={"sub": form_data.username})
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        username = payload.get("sub")
        new_access = create_access_token(data={"sub": username})
        new_refresh = create_refresh_token(data={"sub": username})
        return {"access_token": new_access, "refresh_token": new_refresh}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/books", response_model=List[Book])
async def get_books(current_user: str = Depends(get_current_user)):
    books_cursor = books_collection.find()
    books = []
    async for book in books_cursor:
        book["id"] = str(book["_id"])
        del book["_id"]
        books.append(Book(**book))
    return books

@app.post("/books", response_model=Book)
async def add_book(book: Book, current_user: str = Depends(get_current_user)):
    result = await books_collection.insert_one(book.dict(exclude={"id"}))
    book.id = str(result.inserted_id)
    return book

@app.delete("/books/{book_id}", status_code=204)
async def delete_book(book_id: str, current_user: str = Depends(get_current_user)):
    await books_collection.delete_one({"_id": ObjectId(book_id)})
    return