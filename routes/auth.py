from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, Field
import requests
from backend.config.settings import settings
from backend.database.connection import get_database
from backend.utils.security import hash_password, verify_password, create_access_token
from backend.middleware.auth import get_current_user
from backend.services.threat_monitor import log_security_event

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_ip(request: Request) -> str:
    """Extract client IP from request.state (set by middleware) or fallback."""
    try:
        return request.state.client_ip
    except Exception:
        return request.client.host if request.client else "unknown"


class UserRegister(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict


@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserRegister, request: Request):
    db = get_database()
    ip = _get_ip(request)

    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )
    
    hashed_pw = hash_password(user_data.password)
    user_doc = {
        "name": user_data.name,
        "email": user_data.email,
        "password": hashed_pw,
        "role": "user",
        "created_at": datetime.now(timezone.utc),
        "status": "active"
    }
    
    result = await db.users.insert_one(user_doc)
    user_doc["_id"] = str(result.inserted_id)
    user_doc.pop("password", None)
    
    access_token = create_access_token(data={"sub": user_doc["email"], "role": user_doc["role"]})

    # Log User Registered event
    await log_security_event(
        event_type="user_registered",
        description=f"New user registered: {user_doc['email']}",
        user_id=user_doc["_id"],
        username=user_doc["email"],
        ip_address=ip,
        source_module="auth",
    )

    return {"access_token": access_token, "token_type": "bearer", "user": user_doc}


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    db = get_database()
    ip = _get_ip(request)

    # ── Log Login Attempt BEFORE authentication ──
    await log_security_event(
        event_type="login_attempt",
        description=f"Login attempt for {credentials.email}",
        username=credentials.email,
        ip_address=ip,
        source_module="auth",
    )

    user = await db.users.find_one({"email": credentials.email})
    if not user:
        await log_security_event(
            event_type="login_failure",
            description=f"Failed login for {credentials.email} — user not found",
            severity="medium",
            username=credentials.email,
            ip_address=ip,
            source_module="auth",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password."
        )

    # Check if user is blocked
    if user.get("status") == "blocked":
        await log_security_event(
            event_type="login_failure",
            description=f"Blocked user {credentials.email} attempted login",
            severity="high",
            user_id=str(user["_id"]),
            username=credentials.email,
            ip_address=ip,
            source_module="auth",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been suspended. Contact an administrator."
        )

    if not verify_password(credentials.password, user["password"]):
        await log_security_event(
            event_type="login_failure",
            description=f"Failed login for {credentials.email} — wrong password",
            severity="medium",
            user_id=str(user["_id"]),
            username=credentials.email,
            ip_address=ip,
            source_module="auth",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password."
        )
        
    user["_id"] = str(user["_id"])
    user.pop("password", None)
    
    access_token = create_access_token(data={"sub": user["email"], "role": user.get("role", "user")})

    # ── Log Login Success AFTER successful auth ──
    await log_security_event(
        event_type="login_success",
        description=f"User {user['email']} logged in (role: {user.get('role', 'user')})",
        user_id=user["_id"],
        username=user["email"],
        ip_address=ip,
        source_module="auth",
    )

    return {"access_token": access_token, "token_type": "bearer", "user": user}


@router.get("/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    current_user.pop("password", None)
    return current_user


@router.get("/behavior")
async def get_my_behavior(current_user: dict = Depends(get_current_user)):
    """Fetch behavioral profile for the authenticated user."""
    from backend.services.behavior_analytics import get_user_behavior_profile
    profile = await get_user_behavior_profile(current_user["_id"])
    return profile


class GoogleLoginRequest(BaseModel):
    credential: str


@router.post("/google", response_model=TokenResponse)
async def google_login(payload: GoogleLoginRequest, request: Request):
    db = get_database()
    ip = _get_ip(request)

    # Log Google Login attempt
    await log_security_event(
        event_type="google_login_attempt",
        description="Google login attempt started",
        ip_address=ip,
        source_module="auth",
    )

    # Verify the token using Google tokeninfo API
    id_token = payload.credential
    try:
        response = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}", timeout=5)
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google credential token."
            )
        token_info = response.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to verify Google token: {str(e)}"
        )

    # Check audience matches our Client ID (if settings has GOOGLE_CLIENT_ID)
    client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
    if client_id and token_info.get("aud") != client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Audience mismatch. Invalid token source."
        )

    email = token_info.get("email")
    name = token_info.get("name", email.split("@")[0] if email else "Google User")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account does not provide an email."
        )

    # Check if user exists
    user = await db.users.find_one({"email": email})
    if not user:
        # Register a new user automatically
        import secrets
        # Generate a random password since we use SSO
        dummy_password = secrets.token_urlsafe(16)
        hashed_pw = hash_password(dummy_password)

        user_doc = {
            "name": name,
            "email": email,
            "password": hashed_pw,
            "role": "user",
            "created_at": datetime.now(timezone.utc),
            "status": "active",
            "auth_provider": "google"
        }
        result = await db.users.insert_one(user_doc)
        user = user_doc
        user["_id"] = result.inserted_id

        await log_security_event(
            event_type="user_registered",
            description=f"New user registered via Google: {email}",
            user_id=str(user["_id"]),
            username=email,
            ip_address=ip,
            source_module="auth",
        )
    else:
        # Check if user is blocked
        if user.get("status") == "blocked":
            await log_security_event(
                event_type="login_failure",
                description=f"Blocked user {email} attempted Google login",
                severity="high",
                user_id=str(user["_id"]),
                username=email,
                ip_address=ip,
                source_module="auth",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account has been suspended. Contact an administrator."
            )

    user["_id"] = str(user["_id"])
    user.pop("password", None)

    access_token = create_access_token(data={"sub": user["email"], "role": user.get("role", "user")})

    await log_security_event(
        event_type="login_success",
        description=f"User {email} logged in via Google SSO",
        user_id=user["_id"],
        username=email,
        ip_address=ip,
        source_module="auth",
    )

    return {"access_token": access_token, "token_type": "bearer", "user": user}

