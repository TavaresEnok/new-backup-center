import re
from datetime import datetime, timedelta
from typing import Optional, Any, Union
from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from app.core.config import settings

# Password Hashing
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Encryption for device passwords
# Generate a key: Fernet.generate_key().decode()
try:
    cipher_suite = Fernet(settings.ENCRYPTION_KEY.encode())
except Exception as exc:
    raise RuntimeError("Invalid ENCRYPTION_KEY. Generate one with Fernet.generate_key().") from exc

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def validate_password_strength(password: str) -> str | None:
    value = str(password or '')
    if len(value) < 8:
        return 'A senha deve ter pelo menos 8 caracteres.'
    if not re.search(r'[A-Z]', value):
        return 'A senha deve ter pelo menos 1 letra maiuscula.'
    if not re.search(r'[a-z]', value):
        return 'A senha deve ter pelo menos 1 letra minuscula.'
    if not re.search(r'\d', value):
        return 'A senha deve ter pelo menos 1 numero.'
    if not re.search(r'[^A-Za-z0-9]', value):
        return 'A senha deve ter pelo menos 1 caractere especial.'
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def encrypt_password(password: str) -> str:
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    return cipher_suite.decrypt(encrypted_password.encode()).decode()
