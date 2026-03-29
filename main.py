from fastapi import FastAPI
from database import engine
from models import Base
from security import hash_password, verify_password
from auth_routes import router as auth_router
from document_routes import router as document_router

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(auth_router)
app.include_router(document_router)

@app.get("/")
def read_root():
    return {"message": "Secura backend running successfully"}

@app.get("/test-hash")
def test_hash():
    password = "TestPassword123"
    hashed = hash_password(password)
    valid = verify_password("TestPassword123", hashed)

    return {
        "hashed_password": hashed,
        "password_valid": valid
    }