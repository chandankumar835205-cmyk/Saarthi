import enum
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (Boolean, Column, DateTime, Enum, Float, ForeignKey,
                        Integer, String, create_engine, text)
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session

# --- Configuration ---
SQLALCHEMY_DATABASE_URL = "postgresql://civic_sathi_db_test_user:zcX8yhSmabkCbryAFNir4c3edVtDVYl7@dpg-d3a4mdjipnbc739af8ng-a.singapore-postgres.render.com/civic_sathi_db_test"
SECRET_KEY = "6a0991bf60f6d7424c01730e5bf48b2a4dadf30affd4269f107eb1336f6ada3c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Database Setup ---
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"sslmode": "require"}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Enums ---
class EmployeeRole(str, enum.Enum):
    admin = "admin"
    employee = "employee"
    super_admin = "super_admin"
    staff = "staff"
    department_head = "department_head"

class IssueStatus(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    resolved = "resolved"

# --- SQLAlchemy ORM Models ---
class User(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(EmployeeRole, name="employeerole"), nullable=False)
    department = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    issues = relationship("Issue", back_populates="submitter", cascade="all, delete-orphan")

class Issue(Base):
    __tablename__ = "issues"
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String, nullable=False)
    department = Column(String, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    photo_url = Column(String, nullable=True)
    audio_url = Column(String, nullable=True)
    status = Column(Enum(IssueStatus, name="issuestatus"), default=IssueStatus.pending, nullable=False)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("employees.id"))
    submitter = relationship("User", back_populates="issues")

# --- Pydantic Schemas ---
class UserBase(BaseModel):
    email: str
    role: EmployeeRole
    department: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserSchema(UserBase):
    id: int
    is_active: bool
    class Config: from_attributes = True

class IssueBase(BaseModel):
    description: str
    department: str
    latitude: float
    longitude: float
    photo_url: Optional[str] = None
    audio_url: Optional[str] = None

class IssueCreate(IssueBase): pass
class IssueUpdate(BaseModel): status: IssueStatus

class IssueSchema(IssueBase):
    id: int
    status: IssueStatus
    submitted_at: datetime
    user_id: int
    class Config: from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserLoginResponse(Token):
    user_role: EmployeeRole
    user_email: str

# --- Security & Auth ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(pwd): return pwd_context.hash(pwd)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(**user.model_dump(exclude={"password"}), hashed_password=hashed_password, is_active=True)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None or not user.is_active: raise credentials_exception
    return user

# --- FastAPI App ---
app = FastAPI(title="Web Portal Backend")
origins = [
    "https://chandankumar835205-cmyk.github.io",  # your deployed frontend
    "http://127.0.0.1:5500",  # optional: local testing
]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# --- SPECIAL ONE-TIME DATABASE UPDATE ENDPOINT ---
# This endpoint will run the necessary SQL command to update your database.
@app.post("/admin/update-db", tags=["Admin"])
def update_database_schema(db: Session = Depends(get_db)):
    """
    Adds the 'department_head' value to the 'employeerole' enum type in the database.
    This is a one-time operation.
    """
    try:
        # We use a raw text query to execute the ALTER TYPE command.
        db.execute(text("ALTER TYPE employeerole ADD VALUE 'department_head';"))
        db.commit()
        return {"status": "success", "message": "Database schema updated successfully. The 'department_head' role has been added."}
    except ProgrammingError as e:
        # This error occurs if the value already exists, which is fine.
        if "already exists" in str(e):
            return {"status": "skipped", "message": "The 'department_head' role already exists in the database. No action was needed."}
        # For any other database error, we raise it.
        raise HTTPException(status_code=500, detail=f"A database error occurred: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

# --- Regular API Endpoints ---
@app.post("/token", response_model=UserLoginResponse, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "user_role": user.role, "user_email": user.email}

@app.post("/users/", response_model=UserSchema, status_code=status.HTTP_201_CREATED, tags=["Users"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_email(db, email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db=db, user=user)

@app.get("/users/me/", response_model=UserSchema, tags=["Users"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/issues/", response_model=IssueSchema, status_code=status.HTTP_201_CREATED, tags=["Issues"])
def create_issue(issue: IssueCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_issue = Issue(**issue.model_dump(), user_id=current_user.id)
    db.add(db_issue)
    db.commit()
    db.refresh(db_issue)
    return db_issue

@app.get("/issues/", response_model=List[IssueSchema], tags=["Issues"])
def read_issues(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Issue)
    if current_user.role == EmployeeRole.department_head:
        if not current_user.department: raise HTTPException(status_code=400, detail="User not assigned to a department.")
        query = query.filter(Issue.department == current_user.department)
    return query.offset(skip).limit(limit).all()

# (The rest of the endpoints are unchanged)
@app.get("/issues/{issue_id}", response_model=IssueSchema, tags=["Issues"])
def read_issue(issue_id: int, db: Session = Depends(get_db)):
    db_issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if db_issue is None: raise HTTPException(status_code=404, detail="Issue not found")
    return db_issue

@app.put("/issues/{issue_id}", response_model=IssueSchema, tags=["Issues"])
def update_issue_status(issue_id: int, issue_update: IssueUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role not in [EmployeeRole.admin, EmployeeRole.super_admin, EmployeeRole.department_head]:
        raise HTTPException(status_code=403, detail="Not authorized to update issue status")
    db_issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if db_issue is None: raise HTTPException(status_code=4.04, detail="Issue not found")
    db_issue.status = issue_update.status
    db.commit()
    db.refresh(db_issue)
    return db_issue

@app.delete("/issues/{issue_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Issues"])
def delete_issue(issue_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != EmployeeRole.super_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete issues")
    db_issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if db_issue is None: raise HTTPException(status_code=404, detail="Issue not found")
    db.delete(db_issue)
    db.commit()
    return None

