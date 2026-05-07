from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm      # For handling OAuth2 authentication
from security import hash_password, verify_password, create_access_token, decode_access_token
from database import SessionLocal
from models import User

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")      #OAuth2 scheme extracts bearer tokens from protected requests
blacklisted_tokens = set()      #invalidate tokens on logout 

#every request made is passed through this function to verify the token and extract user info
def get_current_user(token: str = Depends(oauth2_scheme)):
    if token in blacklisted_tokens:
        raise HTTPException(status_code=401, detail="Token has been logged out")
    
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return payload

#check if user met his role permissions
def require_role(required_role: str):
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role")

        print("TOKEN ROLE:", user_role)
        print("REQUIRED ROLE:", required_role)

        if not user_role or user_role.lower() != required_role:
            raise HTTPException(status_code=403, detail="Access Denied")
        
        return current_user
    
    return role_checker

#register doctor endpoint
@router.post("/register")
def register_user(username: str, email: str, password: str, role: str, current_user: dict = Depends(require_role("admin"))):
    db = SessionLocal()
    role = role.lower()
    
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = hash_password(password)
    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.close()

    return {"message": "User registered successfully"}

#register patient endpoint
@router.post("/patient-register")
def register_user(username: str, email: str, password: str):
    db = SessionLocal()
    role = "patient"

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = hash_password(password)
    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.close()

    return {"message": "User registered successfully"}

#login user endpoint
@router.post("/login")
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()

    if not user:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user.hashed_password):
        db.close()
        raise HTTPException(status_code=400, detail="Invalid username or password")

    #create token using their username, role and user id as payload
    token = create_access_token(data={
        "sub": user.username,
        "role": user.role,
        "user_id": user.id
    })

    db.close()
    return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username, "user_id": user.id}

#get current user endpoint
@router.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user.get("sub"),
        "role": current_user.get("role"),
        "user_id": current_user.get("user_id")
    }

#logout endpoint
@router.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme)):
    blacklisted_tokens.add(token)
    return {"message": "Logged out successfully"}
