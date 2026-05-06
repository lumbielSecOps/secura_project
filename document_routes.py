from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse
from cryptography.fernet import Fernet
from fastapi.encoders import jsonable_encoder
from database import SessionLocal
from models import Document, Audit_Log, User
from datetime import datetime
from auth_routes import get_current_user, require_role
import os, mimetypes

router = APIRouter()

# define upload and decrypted file directorires and key file for encryption
UPLOAD_DIR = "uploads"
DECRYPT_DIR = "decrypted"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DECRYPT_DIR, exist_ok=True)

KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

    else: 
            with open(KEY_FILE, "rb") as key_file:
                key = key_file.read()

    return key

fernet = Fernet(load_key())

#send encrypted document
@router.post("/send-document")
async def send_document(
    receiver_id: int = Form(...),
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("doctor"))
):
    db = SessionLocal()

    sender_id = current_user.get("user_id")

    # validate that sender and receiver are not the same 
    if sender_id == receiver_id:
        db.close()
        raise HTTPException(status_code=400, detail="Sender and receiver cannot be the same")

    # validate that the uploaded file has an extension
    if "." not in file.filename:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid document: file extension is required")

    # read the file content
    file_content = await file.read()

    # encrypt the file content using Fernet symmetric encryption
    encrypted_content = fernet.encrypt(file_content)

    # save the encrypted file to the uploads directory with a unique name
    encrypted_filename = f"encrypted_{datetime.now().timestamp()}_{file.filename}"
    encrypted_path = os.path.join(UPLOAD_DIR, encrypted_filename)

    # write the encrypted content to the file
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_content)

    # create a new document record in the database
    new_document = Document(
        filename=file.filename,
        file_path=encrypted_path,
        sender_id=sender_id,
        receiver_id=receiver_id,
        status="sent"
    )

    # log the action in the audit log
    db.add(new_document)
    db.commit()

    new_log = Audit_Log(
        user_id=sender_id,
        action="Send_encrypted_document",
        timestamp=str(datetime.now())
    )

    # add the log to the database
    db.add(new_log)
    db.commit()
    db.close()

    return {
        "message": "Encrypted document uploaded and sent successfully",
        "filename": file.filename,
        "receiver_id": receiver_id
    }

#get documents
@router.get("/documents/{receiver_id}")
def get_documents(receiver_id: int, current_user: dict = Depends(require_role("patient"))):
    db = SessionLocal()

    if current_user.get("user_id") != receiver_id:
        db.close()
        raise HTTPException(status_code=403, detail="Only patients can retrieve and view their own documents")

    documents = db.query(Document).filter(Document.receiver_id == receiver_id).all()

    if not documents:
        db.close()
        return {"message": "No documents found for this user"}

    documents_data = [jsonable_encoder(document) for document in documents]

    # log the action
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
        "documents": documents_data
    }

#download and decrypt document
@router.get("/download-document/{document_id}")
def download_document(
    document_id: int,
    current_user: dict = Depends(require_role("patient"))
):
    db = SessionLocal()

    document = db.query(Document).filter(Document.id == document_id).first()

    if not document:
        db.close()
        raise HTTPException(status_code=404, detail="Document not found")

    if document.receiver_id != current_user.get("user_id"):
        db.close()
        raise HTTPException(status_code=403, detail="You can only download your own documents")

    with open(document.file_path, "rb") as f:
        encrypted_content = f.read()

    decrypted_content = fernet.decrypt(encrypted_content)

    safe_decrypted_filename = f"decrypted_{document.id}_{document.filename}"
    decrypted_path = os.path.join(DECRYPT_DIR, safe_decrypted_filename)

    with open(decrypted_path, "wb") as f:
        f.write(decrypted_content)

    new_log = Audit_Log(
        user_id=current_user.get("user_id"),
        action="Download_decrypted_document",
        timestamp=str(datetime.now())
    )

    db.add(new_log)
    db.commit()

    original_filename = document.filename
    
    db.close()

    media_type, _ = mimetypes.guess_type(original_filename)

    return FileResponse(
        decrypted_path,
        media_type=media_type or "application/pdf",
        headers= {"Content-Disposition": f'inline; filename="{original_filename}"'}
    )

#get audit logs
@router.get("/audit-logs")
def get_audit_logs(
    current_user: dict = Depends(require_role("admin"))
):
    db = SessionLocal()

    logs = db.query(Audit_Log).order_by(Audit_Log.id.desc()).all()

    formatted_logs = []

    for log in logs:
        user = db.query(User).filter(User.id == log.user_id).first()

        formatted_logs.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": user.username if user else "Unknown",
            "role": user.role if user else "Unknown",
            "action": log.action,
            "timestamp": log.timestamp
        })

    db.close()

    return {"logs": formatted_logs}