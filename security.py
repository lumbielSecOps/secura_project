from passlib.context import CryptContext    #imports password hashing tool
from jose import JWTError, jwt  #imports JWT handling tools 
from datetime import datetime, timedelta        #imports datetime tools for token expiration handling
import os                 #imports os for environment variable handling

#hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


SECRET_KEY = os.getenv("SECRET_KEY", "secura-secret-key-change-in-production") #secret key for JWT encoding and decoding, should be set as an environment variable in production
ALGORITHM = "HS256" #JWT algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = 30 #token expiration time in minutes

#changing plaintext password to hashed password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

#verify plaintext password against hashed password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

#create a token 
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

#decode a token
def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None