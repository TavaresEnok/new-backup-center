"""
ApiTokenService — gerenciamento de tokens de API para acesso externo.

Tokens são gerados com `secrets.token_urlsafe`, armazenados apenas como hash.
O valor real é exibido apenas uma vez na criação.
"""

import secrets
from datetime import datetime
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
import uuid

from app.models.api_token import ApiToken
from app.core.security import pwd_context


TOKEN_PREFIX = "bc_"  # "backup center"


class ApiTokenService:

    @staticmethod
    def generate_raw_token() -> str:
        """Gera um token aleatório seguro. Formato: bc_<40 chars>"""
        return TOKEN_PREFIX + secrets.token_urlsafe(40)

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        return pwd_context.hash(raw_token)

    @staticmethod
    def _verify_token(raw_token: str, token_hash: str) -> bool:
        return pwd_context.verify(raw_token, token_hash)

    @staticmethod
    def create_token(
        db: Session,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        name: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[ApiToken, str]:
        """
        Cria um novo API token.

        Returns:
            Tuple[ApiToken, str]: (objeto salvo no banco, token raw para exibir ao usuário)
        """
        raw_token = ApiTokenService.generate_raw_token()
        token_hash = ApiTokenService._hash_token(raw_token)
        prefix = raw_token[:12]  # "bc_" + 9 chars

        token = ApiToken(
            tenant_id=tenant_id,
            user_id=user_id,
            name=name,
            token_prefix=prefix,
            token_hash=token_hash,
            is_active=True,
            expires_at=expires_at,
        )
        db.add(token)
        db.commit()
        db.refresh(token)

        return token, raw_token

    @staticmethod
    def verify_token(db: Session, raw_token: str) -> Optional[ApiToken]:
        """
        Valida um token raw e retorna o ApiToken se válido.
        Atualiza last_used_at automaticamente.

        Returns:
            ApiToken se válido, None caso contrário.
        """
        if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
            return None

        prefix = raw_token[:12]

        # Busca candidatos pelo prefixo (evita verificar todos os hashes)
        candidates = db.query(ApiToken).filter(
            ApiToken.token_prefix == prefix,
            ApiToken.is_active == True,
        ).all()

        for token in candidates:
            if ApiTokenService._verify_token(raw_token, token.token_hash):
                if token.is_expired:
                    return None
                # Atualiza last_used_at
                token.last_used_at = datetime.utcnow()
                db.commit()
                return token

        return None

    @staticmethod
    def list_tokens(db: Session, tenant_id: uuid.UUID) -> List[ApiToken]:
        """Lista todos os tokens de um tenant (ativos e inativos)."""
        return db.query(ApiToken).filter(
            ApiToken.tenant_id == tenant_id
        ).order_by(ApiToken.created_at.desc()).all()

    @staticmethod
    def revoke_token(db: Session, token_id: uuid.UUID, tenant_id: uuid.UUID) -> bool:
        """
        Revoga (desativa) um token.
        Valida que o token pertence ao tenant antes de revogar.
        """
        token = db.query(ApiToken).filter(
            ApiToken.id == token_id,
            ApiToken.tenant_id == tenant_id,
        ).first()

        if not token:
            return False

        token.is_active = False
        db.commit()
        return True

    @staticmethod
    def get_token(db: Session, token_id: uuid.UUID, tenant_id: uuid.UUID) -> Optional[ApiToken]:
        return db.query(ApiToken).filter(
            ApiToken.id == token_id,
            ApiToken.tenant_id == tenant_id,
        ).first()
