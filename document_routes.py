from fastapi import APIRouter, HTTPException
from database import SessionLocal
from models import Document, Audit_Log
from datetime import datetime

router = APIRouter()

@router.post("/send-document")
def send_document(filename: str, file_path: str, sender_id: int, receiver_id: int):
    db = SessionLocal()

    # validate filename
    if "." not in filename:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid document: document extension is required")

    # validate doc_path
    if "." not in file_path or ("/" not in file_path and "\\" not in file_path):
        db.close()
        raise HTTPException(status_code=400, detail="Invalid file path")

    # prevent sender and receiver being the same
    if sender_id == receiver_id:
        db.close()
        raise HTTPException(status_code=400, detail="Sender and receiver cannot be the same")

    new_document = Document(
        filename=filename,
        file_path=file_path,
        sender_id=sender_id,
        receiver_id=receiver_id,
        status="sent"
    )

    db.add(new_document)
    db.commit()

    new_log = Audit_Log(
        user_id=sender_id,
        action="Send_document",
        timestamp=str(datetime.now())
    )
    db.add(new_log)
    db.commit()
    db.close()

    return {"message": "Document sent successfully"}

@router.get("/documents/{receiver_id}")
def get_documents(receiver_id: int):
    db = SessionLocal()

    documents = db.query(Document).filter(Document.receiver_id == receiver_id).all()

    db.close()

    if not documents:
        return {"message": "No documents found for this user"}

    new_log = Audit_Log(
        user_id=receiver_id,
        action="View_document",
        timestamp=str(datetime.now())
    )
    db.add(new_log)
    db.commit()
    db.close()
   
    return {
        "message": "Documents retrieved successfully",
        "documents": documents
    }

   
