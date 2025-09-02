
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
import json, os

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import FileResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Any

from sqlalchemy import create_engine, Column, Integer, String, Enum as SAEnum, ForeignKey, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# --- Config ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_SECRET")
JWT_ALG = "HS256"
ACCESS_MIN = int(os.getenv("ACCESS_MIN", "1440"))

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "docutrack")
PG_USER = os.getenv("POSTGRES_USER", "docu_user")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "docu_pass")

DATABASE_URL = os.getenv("DATABASE_URL") or f"postgresql+psycopg2://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{PG_DB}"

UPLOAD_DIR = Path("./data/uploads")
CERT_DIR = Path("./data/certificates")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
CERT_DIR.mkdir(parents=True, exist_ok=True)

# --- DB ---
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()

class Role(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"

class RequestStatus(str, Enum):
    RECEIVED = "RECEIVED"
    DATABASE_URL = os.getenv("DATABASE_URL") or f"postgresql+psycopg2://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{PG_DB}"
    APPROVED = "APPROVED"
    # Puerto configurable para Render
    APP_PORT = int(os.getenv("PORT", "8000"))
    REJECTED = "REJECTED"
    CORRECTION_REQUESTED = "CORRECTION_REQUESTED"
    ISSUED = "ISSUED"




class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(SAEnum(Role), nullable=False, default=Role.USER)
    created_at = Column(DateTime, default=datetime.utcnow)
    requests = relationship("CertificateRequest", back_populates="user")


class CertificateRequest(Base):
    __tablename__ = "certificate_requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    certificate_type = Column(String(100), nullable=False)
    data_json = Column(Text, nullable=False)
    status = Column(SAEnum(RequestStatus), nullable=False, default=RequestStatus.RECEIVED)
    certificate_pdf_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="requests")

# --- Auth utils ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, ph: str) -> bool:
    return pwd_context.verify(p, ph)


def create_token(sub: str, role: Role) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_MIN)
    return jwt.encode({"sub": sub, "role": role.value, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALG])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2)) -> User:
    try:
        payload = decode_token(token)
        uid = int(payload.get("sub"))
        user = db.get(User, uid)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(*roles: Role):
    def _inner(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _inner

# --- Schemas ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]
    role: Role

class RequestCreate(BaseModel):
    certificate_type: str
    data: Any

class RequestOut(BaseModel):
    id: int
    certificate_type: str
    data_json: str
    status: RequestStatus
    certificate_pdf_path: Optional[str] = None

class AdminUpdateStatus(BaseModel):
    status: RequestStatus

# --- PDF ---
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

def generate_pdf(out_path: Path, citizen_name: str, certificate_type: str, request_id: int, payload: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    w, h = LETTER
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(w/2, h-100, "CERTIFICADO OFICIAL")
    c.setFont("Helvetica", 12)
    c.drawString(72, h-150, f"Tipo: {certificate_type}")
    c.drawString(72, h-170, f"Solicitante: {citizen_name}")
    c.drawString(72, h-190, f"Trámite ID: {request_id}")
    c.drawString(72, h-210, f"Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    c.drawString(72, h-250, "Datos:")
    text = c.beginText(72, h-270)
    text.setFont("Helvetica", 10)
    for line in payload.splitlines():
        text.textLine(line[:120])
    c.drawText(text)
    c.showPage()
    c.save()

# --- FastAPI ---
app = FastAPI(title="DocuTrack Simple", openapi_url="/api/openapi.json")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True
)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email=="admin@demo.com").first():
            db.add(User(email="admin@demo.com", password_hash=hash_password("admin123"), role=Role.ADMIN))
            db.commit()
    finally:
        db.close()

# --- Endpoints ---
@app.post("/api/auth/register", response_model=MeOut)
def register(p: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email==p.email).first():
        raise HTTPException(400, "Email exists")
    u = User(email=p.email, password_hash=hash_password(p.password), full_name=p.full_name, role=Role.USER)
    db.add(u); db.commit(); db.refresh(u)
    return MeOut(id=u.id, email=u.email, full_name=u.full_name, role=u.role)

@app.post("/api/auth/login", response_model=TokenOut)
def login(p: UserLogin, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email==p.email).first()
    if not u or not verify_password(p.password, u.password_hash):
        raise HTTPException(400, "Invalid credentials")
    return TokenOut(access_token=create_token(str(u.id), u.role))

@app.get("/api/auth/me", response_model=MeOut)
def me(user: User = Depends(get_current_user)):
    return MeOut(id=user.id, email=user.email, full_name=user.full_name, role=user.role)

@app.post("/api/requests", response_model=RequestOut)
def create_request(p: RequestCreate, user: User = Depends(require_role(Role.USER)), db: Session = Depends(get_db)):
    req = CertificateRequest(user_id=user.id, certificate_type=p.certificate_type, data_json=json.dumps(p.data))
    db.add(req); db.commit(); db.refresh(req)
    return RequestOut(id=req.id, certificate_type=req.certificate_type, data_json=req.data_json, status=req.status, certificate_pdf_path=req.certificate_pdf_path)

@app.get("/api/requests", response_model=List[RequestOut])
def my_requests(user: User = Depends(require_role(Role.USER)), db: Session = Depends(get_db)):
    rows = db.query(CertificateRequest).filter(CertificateRequest.user_id==user.id).all()
    return [RequestOut(id=r.id, certificate_type=r.certificate_type, data_json=r.data_json, status=r.status, certificate_pdf_path=r.certificate_pdf_path) for r in rows]

@app.get("/api/requests/{rid}/certificate")
def download_cert(rid: int, user: User = Depends(require_role(Role.USER)), db: Session = Depends(get_db)):
    r = db.get(CertificateRequest, rid)
    if not r or r.user_id!=user.id: raise HTTPException(404)
    if r.status!=RequestStatus.ISSUED or not r.certificate_pdf_path: raise HTTPException(400, "Not ready")
    return FileResponse(r.certificate_pdf_path, media_type="application/pdf")

@app.get("/api/admin/requests", response_model=List[RequestOut])
def all_requests(_: User = Depends(require_role(Role.ADMIN)), db: Session = Depends(get_db)):
    rows = db.query(CertificateRequest).all()
    return [RequestOut(id=r.id, certificate_type=r.certificate_type, data_json=r.data_json, status=r.status, certificate_pdf_path=r.certificate_pdf_path) for r in rows]

@app.patch("/api/admin/requests/{rid}/status", response_model=RequestOut)
def update_status(rid: int, p: AdminUpdateStatus, _: User = Depends(require_role(Role.ADMIN)), db: Session = Depends(get_db)):
    r = db.get(CertificateRequest, rid)
    if not r: raise HTTPException(404)
    r.status = p.status; r.updated_at=datetime.utcnow()
    if r.status==RequestStatus.ISSUED:
        cert_path = CERT_DIR / f"cert_{r.id}.pdf"
        generate_pdf(cert_path, r.user.full_name or r.user.email, r.certificate_type, r.id, r.data_json)
        r.certificate_pdf_path = str(cert_path)
    db.add(r); db.commit(); db.refresh(r)
    return RequestOut(id=r.id, certificate_type=r.certificate_type, data_json=r.data_json, status=r.status, certificate_pdf_path=r.certificate_pdf_path)
