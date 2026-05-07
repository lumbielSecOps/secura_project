# secura_project

# Secura - Secure Medical Document Sharing System

## Project Overview
Secura is a secure medical document sharing platform developed using FastAPI, HTML, CSS, and JavaScript.  
The system allows doctors to securely send encrypted medical documents to patients while maintaining role-based access control and audit logging.

The platform was designed to improve confidentiality, integrity, and controlled access to sensitive healthcare records.

---

## Features

### Authentication & Security
- JWT-based authentication
- Role-Based Access Control (RBAC)
- Secure password hashing using bcrypt
- Token-based session handling
- Logout token blacklisting

### Doctor Functionalities
- Upload and send encrypted medical documents
- View sent document history
- View doctor profile
- Select registered patients from dropdown list

### Patient Functionalities
- Patient self-registration
- Secure login system
- View received encrypted documents
- Document history filtering
- Patient profile dashboard

### Admin Functionalities
- Register system users
- View registered users
- View stored documents
- Monitor audit logs
- View system overview statistics

### Encryption & Storage
- Uploaded documents are encrypted before storage using Fernet symmetric encryption
- Files stored inside protected uploads directory
- Decryption occurs only during authorized document viewing
- Encryption keys are managed separately from uploaded files

---

## Technologies Used

### Backend
- FastAPI
- SQLAlchemy
- SQLite
- JWT Authentication
- Python Cryptography Libraries

### Frontend
- HTML5
- CSS3
- JavaScript

---

## System Security Features
- Encrypted document storage
- JWT token validation
- Protected API routes
- Role verification middleware
- Audit logging for sensitive actions
- Fernet Symmetric Encryption

---

## Project Structure

```text
secura_project/
│
├── frontend/
├── uploads/
├── auth_routes.py
├── document_routes.py
├── security.py
├── models.py
├── database.py
├── main.py
└── README.md