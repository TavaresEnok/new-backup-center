import json
import uuid

from app import create_flask_app
from app.core.database import SessionLocal
from app.models.activity_log import ActivityLog
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.services.activity_service import ActivityService


def _seed_user_for_activity(slug_prefix: str):
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=f"{slug_prefix}-{uuid.uuid4().hex[:8]}",
            name="Tenant Activity JSON",
            email=f"{slug_prefix}@test.local",
            is_active=True,
        )
        user = User(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            email=f"user-{uuid.uuid4().hex[:8]}@test.local",
            password_hash="x",
            full_name="User JSON",
            role=UserRole.TENANT_ADMIN,
            is_active=True,
        )
        db.add_all([tenant, user])
        db.commit()
        return tenant.id, user.id
    finally:
        db.close()


def test_activity_details_string_is_saved_as_structured_json():
    tenant_id, user_id = _seed_user_for_activity("act-json-string")
    db = SessionLocal()
    try:
        action = f"TEST_JSON_STRING_{uuid.uuid4().hex[:8]}"
        ActivityService.log_action(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            details="Device updated",
            ip_address="10.0.0.1",
        )
        row = db.query(ActivityLog).filter(ActivityLog.action == action).first()
        payload = json.loads(row.details)
        assert payload["message"] == "Device updated"
        assert "resource_type" in payload
        assert "resource_id" in payload
        assert "result" in payload
        assert "request_id" in payload
    finally:
        db.close()


def test_activity_details_dict_keeps_fields_and_includes_request_id():
    app = create_flask_app()
    tenant_id, user_id = _seed_user_for_activity("act-json-dict")

    with app.test_request_context("/fake", headers={"X-Request-ID": "rid-test-123"}):
        db = SessionLocal()
        try:
            action = f"TEST_JSON_DICT_{uuid.uuid4().hex[:8]}"
            ActivityService.log_action(
                db=db,
                tenant_id=tenant_id,
                user_id=user_id,
                action=action,
                details={
                    "resource_type": "device",
                    "resource_id": "abc-123",
                    "result": "success",
                    "message": "Updated device metadata",
                },
                ip_address="10.0.0.2",
            )
            row = db.query(ActivityLog).filter(ActivityLog.action == action).first()
            payload = json.loads(row.details)
            assert payload["resource_type"] == "device"
            assert payload["resource_id"] == "abc-123"
            assert payload["result"] == "success"
            assert payload["message"] == "Updated device metadata"
            assert payload["request_id"] == "rid-test-123"
        finally:
            db.close()

