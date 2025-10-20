"""
ECC Authentication Handler for FastAPI

Optimized for speed and security with ECC cryptography, caching, and constant-time operations.
Async/await support for high concurrency.
"""

import asyncio
import hashlib
import hmac
import secrets
import time
from functools import lru_cache
from threading import Lock
from typing import Dict, Optional

import argon2
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from lru import LRU


class EccAuthConfig:
    """Configuration for ECC authentication"""

    def __init__(self,
                 hash_iterations: int = 100000,
                 token_expiry: int = 3600,
                 cache_size: int = 10000,
                 cache_ttl: int = 300):
        self.hash_iterations = hash_iterations
        self.token_expiry = token_expiry
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl


class EccAuthHandler:
    """
    Enhanced ECC authentication handler for FastAPI

    Features:
    - ECC-based authentication with secp256k1
    - Argon2+BLAKE3 password hashing
    - LRU caching with TTL
    - Constant-time operations
    - Async/await support for high concurrency
    """

    def __init__(self, **kwargs):
        self.config = EccAuthConfig(**kwargs)

        # Initialize ECC key pair
        self._private_key = ec.generate_private_key(ec.SECP256K1())
        self._public_key = self._private_key.public_key()

        # Initialize LRU cache for tokens
        self._token_cache = LRU(self.config.cache_size)

        # Initialize session cache with thread safety
        self._session_cache: Dict[str, Dict] = {}
        self._session_lock = Lock()

        # In-memory user storage (replace with database in production)
        self._users: Dict[str, Dict] = {}
        self._users_lock = Lock()

    def _generate_user_id(self) -> str:
        """Generate secure random user ID"""
        return secrets.token_hex(16)

    def _generate_salt(self) -> bytes:
        """Generate enhanced salt with timestamp"""
        timestamp = str(int(time.time())).encode()
        random_salt = secrets.token_bytes(16)
        return timestamp + random_salt

    async def _hash_password_async(self, password: str, salt: bytes) -> bytes:
        """Async password hashing using Argon2 + BLAKE3"""
        # Run hashing in thread pool to avoid blocking
        loop = asyncio.get_event_loop()

        def hash_sync():
            # Argon2 hashing
            argon2_hasher = argon2.PasswordHasher(
                time_cost=self.config.hash_iterations // 1000,  # Convert to reasonable time cost
                memory_cost=65536,  # 64 MB
                parallelism=4,
                hash_len=32,
                type=argon2.Type.ID,
            )

            argon2_hash = argon2_hasher.hash(password.encode()).encode()

            # Additional BLAKE3 hashing
            blake3_hash = hashlib.blake3(argon2_hash + salt).digest()

            # Combine salt + Argon2 + BLAKE3
            return salt + argon2_hash + blake3_hash

        return await loop.run_in_executor(None, hash_sync)

    def _verify_password(self, password: str, stored_hash: bytes) -> bool:
        """Verify password using constant-time comparison"""
        if len(stored_hash) < 48:  # salt(32) + hash(16)
            return False

        salt = stored_hash[:32]
        expected_hash = stored_hash[32:]

        # For async verification, we'd need to make this async too
        # For now, using sync verification
        computed_hash = self._hash_password_sync(password, salt)

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash[32:], expected_hash)

    def _hash_password_sync(self, password: str, salt: bytes) -> bytes:
        """Sync password hashing for verification"""
        argon2_hasher = argon2.PasswordHasher(
            time_cost=self.config.hash_iterations // 1000,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.Type.ID,
        )

        argon2_hash = argon2_hasher.hash(password.encode()).encode()
        blake3_hash = hashlib.blake3(argon2_hash + salt).digest()

        return salt + argon2_hash + blake3_hash

    def _create_token(self, user_id: str, username: str) -> str:
        """Create ECC-signed JWT token"""
        now = int(time.time())
        payload = {
            'sub': user_id,
            'username': username,
            'iat': now,
            'exp': now + self.config.token_expiry,
        }

        token = jwt.encode(payload, self._private_key, algorithm='ES256')
        return token

    def _verify_token(self, token: str) -> Optional[Dict]:
        """Verify ECC-signed JWT token with caching"""
        # Check cache first
        cache_key = f"token:{hash(token) % self.config.cache_size}"
        cached_result = self._token_cache.get(cache_key)

        if cached_result and cached_result[1] > time.time():
            return cached_result[0]

        try:
            payload = jwt.decode(token, self._public_key, algorithms=['ES256'])

            # Cache the result
            self._token_cache[cache_key] = (payload, time.time() + self.config.cache_ttl)

            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def register(self, username: str, password: str) -> str:
        """
        Register a new user (async)

        Args:
            username: Username for the new user
            password: Password for the new user

        Returns:
            User ID of the newly registered user

        Raises:
            ValueError: If user already exists or validation fails
        """
        if not username or not password:
            raise ValueError("Username and password are required")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        with self._users_lock:
            # Check if user exists
            if username in self._users:
                raise ValueError("User already exists")

            user_id = self._generate_user_id()
            salt = self._generate_salt()
            password_hash = await self._hash_password_async(password, salt)

            # Store user data
            user_data = {
                'id': user_id,
                'username': username,
                'password_hash': password_hash.hex(),
                'created_at': int(time.time()),
            }

            self._users[username] = user_data

        return user_id

    async def authenticate(self, username: str, password: str) -> str:
        """
        Authenticate user and return token (async)

        Args:
            username: Username to authenticate
            password: Password to verify

        Returns:
            JWT token for authenticated user

        Raises:
            ValueError: If authentication fails
        """
        with self._users_lock:
            user_data = self._users.get(username)
            if not user_data:
                raise ValueError("User not found")

        stored_hash = bytes.fromhex(user_data['password_hash'])
        if not self._verify_password(password, stored_hash):
            raise ValueError("Invalid password")

        token = self._create_token(user_data['id'], username)

        # Cache token
        token_key = f"token:{user_data['id']}"
        with self._session_lock:
            self._session_cache[token_key] = {
                'token': token,
                'expires': time.time() + self.config.cache_ttl
            }

        return token

    async def verify_token(self, token: str) -> Dict:
        """
        Verify JWT token and return user data (async)

        Args:
            token: JWT token to verify

        Returns:
            User data dictionary

        Raises:
            ValueError: If token is invalid
        """
        payload = self._verify_token(token)
        if not payload:
            raise ValueError("Invalid or expired token")

        user_id = payload['sub']
        with self._users_lock:
            user_data = None
            for user in self._users.values():
                if user['id'] == user_id:
                    user_data = user
                    break

        if not user_data:
            raise ValueError("User not found")

        return user_data

    async def create_session(self, user_id: str) -> Dict:
        """
        Create secure session for user (async)

        Args:
            user_id: User ID for session

        Returns:
            Session data dictionary
        """
        session_id = secrets.token_hex(16)
        session_key = secrets.token_bytes(32)

        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'session_key': session_key.hex(),
            'created_at': int(time.time()),
            'expires_at': int(time.time()) + 3600,  # 1 hour
        }

        with self._session_lock:
            self._session_cache[session_id] = session_data

        return session_data

    def get_session(self, session_id: str) -> Optional[Dict]:
        """
        Get session data by ID

        Args:
            session_id: Session ID to retrieve

        Returns:
            Session data dictionary or None if not found/expired
        """
        with self._session_lock:
            session_data = self._session_cache.get(session_id)
            if session_data and session_data['expires_at'] > time.time():
                return session_data

            # Clean up expired session
            if session_id in self._session_cache:
                del self._session_cache[session_id]

        return None


# FastAPI dependency for authentication
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict:
    """
    FastAPI dependency to get current authenticated user

    Usage:
        @app.get("/protected")
        async def protected_route(current_user: dict = Depends(get_current_user)):
            return {"message": f"Hello {current_user['username']}"}
    """
    # This would need to be configured with the auth handler instance
    # For now, raise an exception
    raise HTTPException(
        status_code=500,
        detail="Auth handler not configured. Please set up EccAuthHandler instance."
    )