# --- WEB PORTAL BACKEND ---
# This backend is exclusively for the employee web portal.
# It connects to the SAME database as the mobile app to manage issues.

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, String, Enum, DateTime, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict
from jose import JWTError, jwt
from datetime import datetime, timedelta
import enum
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
import os

# --- 1. Database Connection (Mirrors Mobile App) ---
# This connects to the database that your mobile app backend uses.
DB_USER = "civic_sathi_db_user"
DB_PASSWORD = "MCGLXyhZ4Xw6cElqRZZ9S0Pkv5gFZ8LT"
DB_HOST = "dpg-d37sdcggjchc73cho540-a.singapore-postgres.render.com"
DB_NAME = "civic_sathi_db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 2. App and Middleware Setup ---
app = FastAPI(title="Civic Sathi Web Portal API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your web portal's domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 3. Security & Auth Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "8992f74fef2ef011ddc72afa9d0f99218c9a7c01c2bf881e700e41d6c6b55b85" # Use the same key as the mobile backend
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token/employee")

# --- 4. Database Models (Must PERFECTLY match the mobile app's database tables) ---

# Enums (copied for consistency)
class EmployeeRole(str, enum.Enum):
    super_admin = "super_admin"
    department_head = "department_head"
    staff = "staff"

class IssueStatus(str, enum.Enum):
    pending = "Pending"
    in_progress = "In Progress"
    resolved = "Resolved"

# This model represents the 'users' table created by the mobile app.
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    phone_number = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, index=True)
    issues = relationship("Issue", back_populates="submitter")

# This model represents the 'employees' table.
class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(EmployeeRole), nullable=False)
    department = Column(String, nullable=True)

# This model represents the 'issues' table created by the mobile app.
class Issue(Base):
    __tablename__ = "issues"
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String)
    department = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    photo_url = Column(String)
    audio_url = Column(String)
    status = Column(Enum(IssueStatus), default=IssueStatus.pending, nullable=False)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    submitter = relationship("User", back_populates="issues")

# --- CRITICAL: We DO NOT call Base.metadata.create_all(bind=engine) here. ---
# The mobile app backend is responsible for creating tables. This backend only reads/writes to them.

# --- 5. Pydantic Schemas (For data validation) ---
class EmployeeCreate(BaseModel):
    email: str
    password: str
    role: EmployeeRole
    department: Optional[str] = None

class EmployeeResponse(BaseModel):
    email: str
    role: EmployeeRole
    department: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)
    
class EmployeeToken(BaseModel):
    access_token: str
    token_type: str
    user_role: EmployeeRole

class IssueUpdate(BaseModel):
    status: IssueStatus

class IssueResponse(BaseModel):
    id: int
    description: str
    department: str
    latitude: float
    longitude: float
    photo_url: str
    audio_url: str
    status: IssueStatus
    submitted_at: datetime
    user_id: int
    model_config = ConfigDict(from_attributes=True)

# --- 6. Dependencies & Helper Functions ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_employee_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
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

# --- 7. API Endpoints for the Web Portal ---
@app.post("/token/employee", response_model=EmployeeToken)
def login_employee(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(Employee.email == form_data.username).first()
    if not employee or not verify_password(form_data.password, employee.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": employee.email, "role": employee.role.value})
    return {"access_token": access_token, "token_type": "bearer", "user_role": employee.role.value}

@app.get("/issues/all/", response_model=List[IssueResponse])
def get_all_issues(db: Session = Depends(get_db), current_employee: Employee = Depends(get_current_employee_user)):
    query = db.query(Issue)
    if current_employee.role == EmployeeRole.department_head:
        query = query.filter(Issue.department == current_employee.department)
    return query.order_by(Issue.submitted_at.desc()).all()

@app.put("/issues/{issue_id}/status", response_model=IssueResponse)
def update_issue_status(issue_id: int, issue_update: IssueUpdate, db: Session = Depends(get_db), current_employee: Employee = Depends(get_current_employee_user)):
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")

    if current_employee.role == EmployeeRole.department_head and issue.department != current_employee.department:
        raise HTTPException(status_code=403, detail="Not authorized to update this issue")
    if current_employee.role == EmployeeRole.staff:
        raise HTTPException(status_code=403, detail="Not authorized to perform this action")

    issue.status = issue_update.status
    db.commit()
    db.refresh(issue)
    return issue

@app.post("/employees/create/", response_model=EmployeeResponse)
def create_employee(employee: EmployeeCreate, db: Session = Depends(get_db), current_employee: Employee = Depends(get_current_employee_user)):
    if current_employee.role != EmployeeRole.super_admin:
        raise HTTPException(status_code=403, detail="Only a super admin can create new employees")
    
    db_employee = db.query(Employee).filter(Employee.email == employee.email).first()
    if db_employee:
        raise HTTPException(status_code=400, detail="Employee with this email already exists")

    hashed_password = get_password_hash(employee.password)
    new_employee = Employee(**employee.model_dump(exclude={"password"}), hashed_password=hashed_password)
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)
    return new_employee

@app.get("/")
def read_root():
    return {"message": "Welcome to the Civic Sathi Web Portal Backend!"}

