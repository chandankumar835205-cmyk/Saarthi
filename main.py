# This main.py has been simplified to only manage the 'employees' table.
# All logic for citizen users has been removed as requested.

import os
import shutil
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine, Column, Integer, String, Enum, DateTime
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict # <-- CORRECTED THIS LINE
from jose import JWTError, jwt
from datetime import datetime, timedelta
import enum
from typing import List
from fastapi.staticfiles import StaticFiles

# --- 1. App and Middleware Setup ---
app = FastAPI()

os.makedirs("static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

origins = [
    "http://localhost",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
    "null",
    "https://chandankumar835205-cmyk.github.io",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. Database Setup ---
DB_USER = "civic_sathi_db_user"
DB_PASSWORD = "MCGLXyhZ4Xw6cElqRZZ9S0Pkv5gFZ8LT"
DB_HOST = "dpg-d37sdcggjchc73cho540-a.singapore-postgres.render.com"
DB_NAME = "civic_sathi_db"

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 3. Security & Password Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "a-very-secret-key-that-you-should-change"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 4. Database Models (SQLAlchemy) ---

# -- Roles --
class EmployeeRole(str, enum.Enum):
    admin = "admin"
    departhead = "departhead"
    staff = "staff"

class IssueStatus(str, enum.Enum):
    pending = "Pending"
    in_progress = "In Progress"
    resolved = "Resolved"

# -- The single table for all web portal employees --
class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(Enum(EmployeeRole), nullable=False)
    department = Column(String, nullable=True)

class Issue(Base):
    __tablename__ = "issues"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    location = Column(String)
    department = Column(String)
    status = Column(Enum(IssueStatus), default=IssueStatus.pending)
    created_at = Column(DateTime, default=datetime.utcnow)
    image_url = Column(String, nullable=True)
    audio_url = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- 5. Data Schemas (Pydantic) ---
class IssueBase(BaseModel):
    title: str
    description: str
    location: str
    department: str
    image_url: str | None = None
    audio_url: str | None = None

class IssueCreate(IssueBase):
    pass

class IssueUpdate(BaseModel):
    status: IssueStatus

class IssueResponse(IssueBase):
    id: int
    created_at: datetime
    status: IssueStatus
    model_config = ConfigDict(from_attributes=True)

class EmployeeCreate(BaseModel):
    email: str
    password: str
    role: EmployeeRole
    department: str | None = None

class EmployeeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: str
    role: EmployeeRole
    department: str | None = None

class TokenData(BaseModel):
    email: str | None = None

# --- 6. Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_employee(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    employee = db.query(Employee).filter(Employee.email == email).first()
    if employee is None:
        raise credentials_exception
    return employee

# --- 7. API Endpoints ---
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Simplified to only check the employees table
    employee = db.query(Employee).filter(Employee.email == form_data.username).first()
    if not employee or not verify_password(form_data.password, employee.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    
    access_token = create_access_token(
        data={"sub": employee.email, "role": employee.role.value}
    )
    return {"access_token": access_token, "token_type": "bearer", "user_role": employee.role.value}


@app.post("/employees/", response_model=EmployeeResponse)
def create_employee_user(employee: EmployeeCreate, db: Session = Depends(get_db)):
    # This endpoint is now the only way to create users.
    # In a real app, this should be protected so only admins can use it.
    db_employee = db.query(Employee).filter(Employee.email == employee.email).first()
    if db_employee:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = pwd_context.hash(employee.password)
    new_employee = Employee(
        email=employee.email,
        hashed_password=hashed_password,
        role=employee.role,
        department=employee.department
    )
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)
    return new_employee


@app.get("/issues/", response_model=List[IssueResponse])
def read_issues(
    db: Session = Depends(get_db),
    current_employee: Employee = Depends(get_current_employee)
):
    query = db.query(Issue)
    if current_employee.role == EmployeeRole.departhead:
        query = query.filter(Issue.department == current_employee.department)
    
    issues = query.all()
    return issues


@app.put("/issues/{issue_id}", response_model=IssueResponse)
def update_issue_status(
    issue_id: int,
    issue_update: IssueUpdate,
    db: Session = Depends(get_db),
    current_employee: Employee = Depends(get_current_employee)
):
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if issue is None:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    # Security check: only allow dept heads to edit issues in their own dept
    if current_employee.role == EmployeeRole.departhead and issue.department != current_employee.department:
        raise HTTPException(status_code=403, detail="Not authorized to update this issue")

    issue.status = issue_update.status
    db.commit()
    db.refresh(issue)
    return issue

