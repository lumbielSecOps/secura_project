from fastapi import APIRouter, HTTPException
from security import hash_password, verify_password
from database import SessionLocal
from models import User
router = APIRouter()

@router.post("/register")
def register_user(username: str, email: str, password: str, role: str):

    # open database session
    db = SessionLocal()

    # check if username exists
    existing_user = db.query(User).filter(User.username == username).first()

    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    # check if email exists
    existing_email = db.query(User).filter(User.email == email).first()

    if existing_email:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    # hash the password
    hashed_password = hash_password(password)

    # create user object
    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        role=role
    )

    # save user to database
    db.add(new_user)
    db.commit()

    # close database session
    db.close()

    return {"message": "User registered successfully"}

@router.post("/login")
def login_user(username: str, password: str):

    # open database session
    db = SessionLocal()

    # find user by username
    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username orpassword")

    return {"message": "Login successful"}

# close database session
    db.close()