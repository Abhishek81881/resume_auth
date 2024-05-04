from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
import sqlite3

load_dotenv()

# Initialize FastAPI app
app = FastAPI()
# Create users table
DATABASE_URL = os.getenv("DATABASE_URL")
conn = sqlite3.connect(DATABASE_URL)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT, email TEXT PRIMARY KEY, password TEXT)''')
conn.commit()

# JWT secret key
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User model
class User(BaseModel):
    username: str
    email: str
    password: str

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# User in DB model
class UserInDB(User):
    hashed_password: str

# User database functions
def get_user(email: str):
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    if user:
        return UserInDB(username=user[0], email=user[1], hashed_password=user[2])

def create_user(user: UserInDB):
    hashed_password = pwd_context.hash(user.password)
    cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (user.username, user.email, hashed_password))
    conn.commit()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes
@app.post("/register/")
def register_user(user: User):
    existing_user = get_user(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    create_user(user)
    return {"message": "User created"}

@app.post("/token/")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Mock resume update endpoint
@app.put("/update_resume/")
def update_resume(resume_data: dict, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        # Add logic to update resume using resume_data
        return {"message": "Resume updated successfully"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

if __name__ == "__main__":

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
