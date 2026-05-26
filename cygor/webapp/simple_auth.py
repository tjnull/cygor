"""
Simple token-based authentication for Cygor Web Application.

No username/password required - just a single access token.
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException, Request
from pathlib import Path

# Token storage file
TOKEN_FILE = Path.home() / ".cygor" / "web_token.txt"
# JWT secret key storage file
JWT_SECRET_FILE = Path.home() / ".cygor" / "jwt_secret.txt"

def get_or_create_jwt_secret() -> str:
    """
    Get or create a persistent JWT secret key.
    The key is stored in a file to ensure consistency across requests.
    """
    # First, check environment variable
    secret = os.getenv("CYGOR_JWT_SECRET")
    if secret:
        return secret
    
    # Ensure directory exists
    JWT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Try to read existing secret from file
    if JWT_SECRET_FILE.exists():
        try:
            secret = JWT_SECRET_FILE.read_text().strip()
            if secret:
                return secret
        except Exception:
            pass
    
    # Generate new secret and save it
    secret = secrets.token_urlsafe(64)
    JWT_SECRET_FILE.write_text(secret)
    JWT_SECRET_FILE.chmod(0o600)  # Read/write for owner only
    
    # Only warn user if authentication is enabled
    if os.getenv("CYGOR_AUTH_LOGIN") == "1":
        print("\n" + "="*80)
        print("CYGOR JWT SECRET KEY")
        print("="*80)
        print("[!] No JWT secret key configured!")
        print("")
        print("A secure key has been generated and saved:")
        print(f"   {secret}")
        print("")
        print(f"[*] Key stored in: {JWT_SECRET_FILE}")
        print("")
        print("[*] To set a custom key, add to your environment:")
        print("")
        print(f"   export CYGOR_JWT_SECRET='your-secret-key'")
        print("")
        print("Or add to .env file:")
        print(f"   CYGOR_JWT_SECRET=your-secret-key")
        print("")
        print("[!] IMPORTANT: Save this key! Without it, all user sessions will be invalidated.")
        print("="*80 + "\n")
    
    return secret

# JWT configuration - use persistent secret
SECRET_KEY = get_or_create_jwt_secret()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("CYGOR_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours default


def get_or_create_access_token() -> str:
    """
    Get existing access token or create a new one.
    Token is stored in ~/.cygor/web_token.txt
    """
    # Ensure directory exists
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Try to read existing token
    if TOKEN_FILE.exists():
        try:
            token = TOKEN_FILE.read_text().strip()
            if token:
                return token
        except Exception:
            pass
    
    # Generate new token
    token = secrets.token_urlsafe(48)  # 64 characters when base64 encoded
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)  # Read/write for owner only
    
    return token


def initialize_access_token() -> str:
    """
    Initialize and display the access token on startup.
    Returns the token.
    """
    token = get_or_create_access_token()
    return token


def print_access_token_info(token: str):
    """
    Print access token information at the bottom of startup output.
    Called after all other startup messages.
    """
    if os.getenv("CYGOR_AUTH_LOGIN") == "1":
        # Build login URL from server config
        host = os.getenv("CYGOR_WEB_HOST", "localhost")
        port = os.getenv("CYGOR_WEB_PORT", "8080")
        use_https = os.getenv("CYGOR_WEB_HTTPS", "0") == "1"
        protocol = "https" if use_https else "http"

        # Use localhost for display if binding to all interfaces
        display_host = "localhost" if host == "0.0.0.0" else host
        login_url = f"{protocol}://{display_host}:{port}/auth/login"

        print("\n" + "-" * 80)
        print("CYGOR ACCESS TOKEN")
        print("-" * 80)
        print(f"Token: {token}")
        print(f"Login URL: {login_url}")
        print(f"Token file: {TOKEN_FILE}")
        print("WARNING: Keep this token secure! Anyone with this token can access your system.")
        print("-" * 80)


class TokenManager:
    """Manage JWT token creation and validation."""

    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.

        Args:
            data: Data to encode in the token
            expires_delta: Optional custom expiration time

        Returns:
            Encoded JWT token
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        # Use the type from data if provided, otherwise default to "access"
        token_type = data.get("type", "access")
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": token_type
        })

        # Always get the current secret key (may have been reloaded from file)
        secret_key = get_or_create_jwt_secret()
        return jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Always get the current secret key (may have been reloaded from file)
            secret_key = get_or_create_jwt_secret()
            payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid authentication token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )


async def get_current_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Get current authenticated user from request (cookies or headers).
    Uses simple token-based authentication.
    """
    token = None
    
    # Try to get token from cookie first
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        # Cookie format is "Bearer <token>", extract just the token
        if cookie_token.startswith("Bearer "):
            token = cookie_token[7:]
        else:
            token = cookie_token
    
    # If no cookie, try Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        return None

    try:
        # First, try to decode as JWT session token (most common case after login)
        try:
            # Get the current SECRET_KEY to ensure we're using the right one
            current_secret = get_or_create_jwt_secret()
            payload = jwt.decode(token, current_secret, algorithms=[ALGORITHM])
            if payload.get("type") == "session":
                return {
                    "username": payload.get("sub", "cygor_user"),
                    "role": payload.get("role", "admin"),
                    "token_data": payload
                }
        except JWTError:
            pass
        except Exception:
            pass
        
        # If not a JWT token, check if it's the stored access token or a user token
        stored_token = get_or_create_access_token()
        
        # Check if token matches stored access token
        if secrets.compare_digest(token, stored_token):
            # Create a JWT session token
            token_data = {
                "sub": "cygor_user",
                "role": "admin",
                "type": "session"
            }
            session_token = TokenManager.create_access_token(token_data)
            
            # Return user info
            return {
                "username": "cygor_user",
                "role": "admin",
                "token": session_token
            }
        
        return None

    except Exception:
        return None


async def verify_access_token(token: str) -> bool:
    """
    Verify that the provided token matches the stored access token or a user token.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if not token:
        logger.debug("verify_access_token: token is empty")
        return False
    
    token_clean = token.strip()
    
    # Check against stored access token
    stored_token = get_or_create_access_token()
    if stored_token:
        stored_clean = stored_token.strip()
        if secrets.compare_digest(token_clean, stored_clean):
            logger.debug("verify_access_token: token matches stored access token")
            return True
    
    logger.debug("verify_access_token: token does not match stored access token")
    return False

