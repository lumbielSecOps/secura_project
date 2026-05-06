from fastapi.middleware.cors import CORSMiddleware
from database import engine
from models import Base
from security import hash_password, verify_password
from auth_routes import router as auth_router
from document_routes import router as document_router
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
import shutil
import os
import time

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(document_router)

# Basic root endpoint
@app.get("/")
def read_root():
    return {"message": "Secura backend running successfully"}

#testing password hashing
@app.get("/test-hash")
def test_hash():
    password = "TestPassword123"
    hashed = hash_password(password)
    valid = verify_password("TestPassword123", hashed)

    return {
        "hashed_password": hashed,
        "password_valid": valid
    }


