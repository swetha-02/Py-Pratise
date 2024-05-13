from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from models import User
from database import SessionLocal, engine
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

origins = [
    "http://localhost:1200",
    "https://yourfrontenddomain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_content = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class CreateUser(BaseModel):
    username: str
    password: str


def get_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def create_user(db: Session, user: CreateUser):
    password = pwd_content.hash(user.password)
    db_user = User(username=user.username, password=password)
    db.add(db_user)
    db.commit()
    return "complete"


@app.post("/register")
def register_user(user: CreateUser, db: Session = Depends(get_db)):
    db_user = get_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db=db, user=user)


def auth_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not pwd_content.verify(password, user.password):
        return False
    return user


def access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = (
            datetime.utcnow() + expires_delta
        )  # Change from datetime.now(timedelta.UTC) to datetime.utcnow()
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt


@app.post("/token")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = auth_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_tokens = access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")


@app.get("/verify-token/{token}")
async def verify_user_token(token: str):
    verify_token(token=token)
    return {"message": "Token is valid"}
