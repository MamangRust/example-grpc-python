import logging
import uvicorn
import grpc
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Optional
import todo_pb2
import todo_pb2_grpc

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# JWT configurations
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Generate a new hashed password for "password"
hashed_password = bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Fake database for users
fake_users_db = {
    "user1": {
        "username": "user1",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": hashed_password,
        "disabled": False,
    }
}

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Authentication helpers
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception as e:
        logging.error(f"Password verification error: {str(e)}")
        return False

def authenticate_user(fake_db, username: str, password: str):
    logging.debug(f"Attempting to authenticate user: {username}")
    user = fake_db.get(username)
    if not user:
        logging.debug(f"User {username} not found in database")
        return False
    if not verify_password(password, user["hashed_password"]):
        logging.debug(f"Password verification failed for user {username}")
        return False
    logging.debug(f"User {username} authenticated successfully")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logging.debug(f"Created access token for user: {data.get('sub')}")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logging.debug("Decoding JWT token")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logging.error("Username not found in token payload")
            raise credentials_exception
    except JWTError as e:
        logging.error(f"JWT decode error: {str(e)}")
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None:
        logging.error(f"User {username} not found in database")
        raise credentials_exception
    # Include the token in the user data
    user['token'] = token
    logging.debug(f"Successfully retrieved user {username}")
    return user

# gRPC client setup
def get_grpc_stub(token: str):
    try:
        channel = grpc.insecure_channel('localhost:50051')
        stub = todo_pb2_grpc.TodoServiceStub(channel)
        metadata = [('authorization', f'Bearer {token}')]
        logging.debug(f"Created gRPC stub with token: {token[:10]}...")
        return stub, metadata
    except Exception as e:
        logging.error(f"Error creating gRPC stub: {str(e)}")
        raise

# FastAPI endpoints
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    logging.info(f"Login attempt for user: {form_data.username}")
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        logging.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    logging.info(f"Successful login for user: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/todos/")
async def add_todo(id: str, title: str, description: str, current_user: dict = Depends(get_current_user)):
    stub, metadata = get_grpc_stub(current_user['token'])
    try:
        todo = todo_pb2.TodoItem(id=id, title=title, description=description)
        response = stub.AddTodo(todo, metadata=metadata)
        logging.info(f"Added todo with ID: {id}")
        return {"message": response.message}
    except Exception as e:
        logging.error(f"Error adding todo: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding todo")

@app.get("/todos/")
async def get_todos(current_user: dict = Depends(get_current_user)):
    stub, metadata = get_grpc_stub(current_user['token'])
    try:
        response = stub.GetTodos(todo_pb2.Empty(), metadata=metadata)
        todos = [{"id": item.id, "title": item.title, "description": item.description} 
                for item in response.items]
        logging.info(f"Retrieved {len(todos)} todos")
        return {"todos": todos}
    except Exception as e:
        logging.error(f"Error getting todos: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving todos")

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: str, current_user: dict = Depends(get_current_user)):
    stub, metadata = get_grpc_stub(current_user['token'])
    try:
        response = stub.DeleteTodo(todo_pb2.TodoId(id=todo_id), metadata=metadata)
        logging.info(f"Deleted todo with ID: {todo_id}")
        return {"message": response.message}
    except Exception as e:
        logging.error(f"Error deleting todo: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting todo")

if __name__ == "__main__":
    logging.info("Starting FastAPI server")
    uvicorn.run(app, host="0.0.0.0", port=8000)