#testing if fastAPI is working correctly
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Secura backend running successfully"}