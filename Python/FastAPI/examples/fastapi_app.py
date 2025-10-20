"""
FastAPI Integration Example for DegenHF ECC Authentication

This example shows how to integrate the ECC authentication package with FastAPI.
"""

FASTAPI_APP = """
# main.py

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from degenhf_fastapi import EccAuthHandler

app = FastAPI(title="DegenHF ECC Auth API")

# Configure ECC authentication
auth_config = {
    'hash_iterations': 100000,
    'token_expiry': 3600,  # 1 hour
    'cache_size': 10000,
    'cache_ttl': 300,      # 5 minutes
}

auth_handler = EccAuthHandler(**auth_config)

# Pydantic models
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    status: str

class UserResponse(BaseModel):
    id: str
    username: str
    created_at: int

# Custom dependency for current user
async def get_current_user(token: str = Depends(auth_handler._get_token_from_header)):
    try:
        user_data = await auth_handler.verify_token(token)
        return user_data
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/api/auth/register", response_model=dict)
async def register(user: UserRegister):
    \"\"\"User registration endpoint\"\"\"
    try:
        user_id = await auth_handler.register(user.username, user.password)
        return {
            "status": "success",
            "user_id": user_id,
            "message": "User registered successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user: UserLogin):
    \"\"\"User login endpoint\"\"\"
    try:
        token = await auth_handler.authenticate(user.username, user.password)
        return TokenResponse(token=token, status="success")
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/api/auth/profile", response_model=dict)
async def profile(current_user: dict = Depends(get_current_user)):
    \"\"\"Protected user profile endpoint\"\"\"
    return {
        "status": "success",
        "user": {
            "id": current_user["id"],
            "username": current_user["username"],
            "created_at": current_user["created_at"]
        }
    }

@app.post("/api/auth/session", response_model=dict)
async def create_session(current_user: dict = Depends(get_current_user)):
    \"\"\"Create user session endpoint\"\"\"
    try:
        session_data = await auth_handler.create_session(current_user["id"])
        return {
            "status": "success",
            "session": {
                "session_id": session_data["session_id"],
                "expires_at": session_data["expires_at"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/auth/session/{session_id}", response_model=dict)
async def get_session(session_id: str):
    \"\"\"Get session information\"\"\"
    session_data = auth_handler.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    return {
        "status": "success",
        "session": {
            "session_id": session_data["session_id"],
            "user_id": session_data["user_id"],
            "created_at": session_data["created_at"],
            "expires_at": session_data["expires_at"]
        }
    }

@app.get("/health")
async def health_check():
    \"\"\"Health check endpoint\"\"\"
    return {"status": "healthy", "service": "DegenHF ECC Auth API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
"""

if __name__ == '__main__':
    print("FastAPI Integration Example")
    print("=" * 50)
    print()
    print("Create main.py with the following content:")
    print(FASTAPI_APP)
    print()
    print("Install dependencies:")
    print("   pip install fastapi uvicorn pydantic")
    print()
    print("Run the application:")
    print("   python main.py")
    print()
    print("Or with uvicorn:")
    print("   uvicorn main:app --reload")
    print()
    print("Test the endpoints:")
    print("   POST /api/auth/register - Register a new user")
    print("   POST /api/auth/login - Login and get token")
    print("   GET /api/auth/profile - Get user profile (requires Bearer token)")
    print("   POST /api/auth/session - Create session (requires Bearer token)")
    print("   GET /api/auth/session/<session_id> - Get session info")
    print("   GET /docs - Interactive API documentation")