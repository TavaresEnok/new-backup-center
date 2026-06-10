from collections import Counter

from sqlalchemy import and_, asc, desc, nullslast, or_
from sqlalchemy.orm import Session, joinedload
from app.models.device import Device
from app.models.device_type import DeviceType
from app.models.device_group import DeviceGroup
from app.models.schedule import Schedule
from app.models.tenant import Tenant
from app.core.security import encrypt_password, decrypt_password
from app.services.plan_limits_service import PlanLimitsService
from app.services.schedule_utils import compute_next_daily_run_at, sanitize_daily_time
from datetime import datetime
import uuid
from typing import List, Optional, Dict, Any


# Campos de conexao que sofrem com espacos/quebras de linha acidentais (copy-paste).
# Um IP "  10.0.0.1 " ou usuario "admin\n" ia direto pro netmiko/ssh e falhava a
# conexao/autenticacao de forma dificil de diagnosticar. Normalizamos no service para
# proteger TODAS as rotas (web, API, import em massa), nao so uma tela.
# IMPORTANTE: senhas/chaves NUNCA sao normalizadas — podem conter espacos significativos.
_DEVICE_CONNECTION_TEXT_FIELDS = ("ip_address", "username")
_GROUP_CONNECTION_TEXT_FIELDS = ("vpn_server", "vpn_username", "jump_host", "jump_username")


def _clean_connection_text(value: Any) -> Any:
    """Remove espacos/quebras de linha das pontas de um campo de conexao textual.
    Mantem o valor original se nao for string (ex.: None, int de porta)."""
    if isinstance(value, str):
        return value.strip()
    return value


def _sanitize_connection_fields(data: dict, fields: tuple) -> dict:
    """Retorna copia de `data` com os campos de conexao informados normalizados.
    So toca em chaves presentes em `data` (compativel com update parcial)."""
    if not isinstance(data, dict):
        return data
    cleaned = dict(data)
    for field in fields:
        if field in cleaned:
            cleaned[field] = _clean_connection_text(cleaned[field])
    return cleaned


class DeviceService:
    @staticmethod
    def _infer_tenant_daily_schedule_time(db: Session, tenant_id: uuid.UUID) -> str:
        rows = (
            db.query(Schedule.time)
            .join(Device, Device.id == Schedule.device_id)
            .filter(
                Device.tenant_id == tenant_id,
                Device.is_active.isnot(False),
                Device.backup_scheduled == True,
                Schedule.is_active == True,
                Schedule.time.isnot(None),
            )
            .all()
        )
        times = [sanitize_daily_time(row[0]) for row in rows if row and row[0]]
        if times:
            return Counter(times).most_common(1)[0][0]
        return "02:00"

    @staticmethod
    def _ensure_global_daily_schedule(db: Session, device: Device) -> None:
        from app.models.schedule import Schedule, ScheduleFrequency

        schedule = db.query(Schedule).filter(Schedule.device_id == device.id).first()
        inferred_time = DeviceService._infer_tenant_daily_schedule_time(db, device.tenant_id)

        if not schedule:
            schedule = Schedule(device_id=device.id)
            db.add(schedule)

        schedule.frequency = ScheduleFrequency.DAILY
        schedule.time = inferred_time
        schedule.day_of_week = None
        schedule.day_of_month = None
        schedule.is_active = True
        schedule.next_run_at = compute_next_daily_run_at(inferred_time)

    @staticmethod
    def create_device(db: Session, tenant_id: uuid.UUID, data: dict) -> Device:
        PlanLimitsService.ensure_schema()
        tenant = (
            db.query(Tenant)
            .options(joinedload(Tenant.plan))
            .filter(Tenant.id == tenant_id)
            .first()
        )
        if not tenant:
            raise ValueError("Tenant nao encontrado.")
        limit_check = PlanLimitsService.check_can_add_device(db, tenant)
        if not limit_check.allowed:
            raise ValueError(limit_check.reason)

        raw_group_id = data.get('group_id')
        if not raw_group_id:
            raise ValueError("Grupo e obrigatorio para cadastrar dispositivo.")

        try:
            group_uuid = raw_group_id if isinstance(raw_group_id, uuid.UUID) else uuid.UUID(str(raw_group_id))
        except Exception as exc:
            raise ValueError("Grupo invalido para cadastro de dispositivo.") from exc

        group = (
            db.query(DeviceGroup)
            .filter(
                DeviceGroup.id == group_uuid,
                DeviceGroup.tenant_id == tenant_id,
                DeviceGroup.is_active.is_(True),
            )
            .first()
        )
        if not group:
            raise ValueError("Selecione um grupo ativo para cadastrar o dispositivo.")

        data = _sanitize_connection_fields(data, _DEVICE_CONNECTION_TEXT_FIELDS)
        device = Device(
            tenant_id=tenant_id,
            name=str(data['name']).strip(),
            device_type_id=data.get('device_type_id'),
            group_id=group_uuid,
            ip_address=data['ip_address'],
            port=data.get('port', 22),
            username=data['username'],
            password_encrypted=encrypt_password(data['password']),
            use_telnet=data.get('use_telnet', False),
            backup_scheduled=data.get('backup_scheduled', False),
            description=data.get('description'),
            extra_parameters=data.get('extra_parameters', {}),
            tags=data.get('tags', [])
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        if device.backup_scheduled:
            DeviceService._ensure_global_daily_schedule(db, device)
            db.commit()

        return device

    @staticmethod
    def get_tenant_devices(
        db: Session,
        tenant_id: uuid.UUID,
        group_id: uuid.UUID = None,
        subgroup_filter=None,
        search_query: str = None,
        connection_filter: str = None,
        auto_filter: str = None,
        backup_result_filter: str = None,
        history_filter: str = None,
        connection_audit_filter: str = None,
        due_filter: str = None,
        sort_by: str = "name_asc",
        page: int = 1,
        per_page: int = 30,
    ) -> Dict[str, Any]:
        """Return paginated devices for a tenant with basic aggregates."""
        query = db.query(Device).outerjoin(
            DeviceGroup,
            Device.group_id == DeviceGroup.id,
        ).outerjoin(
            DeviceType,
            Device.device_type_id == DeviceType.id,
        ).options(
            joinedload(Device.type),
            joinedload(Device.group),
            joinedload(Device.subgroup),
        ).filter(Device.tenant_id == tenant_id, Device.is_active.isnot(False))
        
        if group_id:
            query = query.filter(Device.group_id == group_id)

        if subgroup_filter is not None:
            if isinstance(subgroup_filter, str) and subgroup_filter.lower() in {"none", "__none__"}:
                query = query.filter(Device.subgroup_id.is_(None))
            elif isinstance(subgroup_filter, uuid.UUID):
                query = query.filter(Device.subgroup_id == subgroup_filter)
            
        if search_query:
            raw_search = str(search_query or "").strip().lower()
            search_query = f"%{search_query}%"
            connection_search_terms = []
            if raw_search in {"vpn", "tunel", "tunnel"}:
                connection_search_terms.extend([
                    DeviceGroup.uses_vpn == True,
                    DeviceGroup.connection_type == "vpn",
                ])
            elif raw_search in {"jump", "jump host", "jumphost", "bastion", "bastiao"}:
                connection_search_terms.extend([
                    DeviceGroup.uses_jump_host == True,
                    DeviceGroup.connection_type.in_(["jump", "jump_host"]),
                ])
            elif raw_search in {"direto", "direct", "direta"}:
                connection_search_terms.extend([
                    Device.group_id.is_(None),
                    DeviceGroup.connection_type == "direct",
                    and_(
                        DeviceGroup.uses_vpn.isnot(True),
                        DeviceGroup.uses_jump_host.isnot(True),
                    ),
                ])
            query = query.filter(
                or_(
                    Device.name.ilike(search_query),
                    Device.ip_address.ilike(search_query),
                    Device.username.ilike(search_query),
                    Device.model.ilike(search_query),
                    Device.description.ilike(search_query),
                    DeviceGroup.name.ilike(search_query),
                    DeviceType.name.ilike(search_query),
                    DeviceType.category.ilike(search_query),
                    DeviceType.script_name.ilike(search_query),
                    *connection_search_terms,
                )
            )

        if connection_filter == "online":
            query = query.filter(Device.last_connection_status == "online")
        elif connection_filter == "offline":
            query = query.filter(Device.last_connection_status.in_(["offline", "error"]))
        elif connection_filter == "unknown":
            query = query.filter(
                or_(
                    Device.last_connection_status.is_(None),
                    Device.last_connection_status == "unknown"
                )
            )
        elif connection_filter == "vpn":
            query = query.filter(
                or_(
                    DeviceGroup.uses_vpn == True,
                    DeviceGroup.connection_type == "vpn",
                )
            )
        elif connection_filter in {"jump", "jump_host"}:
            query = query.filter(
                or_(
                    DeviceGroup.uses_jump_host == True,
                    DeviceGroup.connection_type.in_(["jump", "jump_host"]),
                )
            )
        elif connection_filter == "direct":
            query = query.filter(
                or_(
                    Device.group_id.is_(None),
                    DeviceGroup.connection_type == "direct",
                    and_(
                        DeviceGroup.uses_vpn.isnot(True),
                        DeviceGroup.uses_jump_host.isnot(True),
                    ),
                )
            )

        if auto_filter == "enabled":
            query = query.filter(Device.backup_scheduled == True)
        elif auto_filter == "disabled":
            query = query.filter(Device.backup_scheduled == False)

        if backup_result_filter == "success":
            query = query.filter(Device.last_backup_status == "success")
        elif backup_result_filter == "failed":
            query = query.filter(Device.last_backup_status == "failure")
        elif backup_result_filter == "never":
            query = query.filter(
                or_(
                    Device.last_backup_status.is_(None),
                    Device.last_backup_status.in_(["never", "unknown"])
                )
            )

        if history_filter == "with_history":
            query = query.filter(Device.last_backup_at.isnot(None))
        elif history_filter == "without_history":
            query = query.filter(Device.last_backup_at.is_(None))

        # Filtros da auditoria de conexao (ping/login)
        connection_group = Device.extra_parameters.op('->>')('connection_test_group')
        if connection_audit_filter == "ping_ok":
            query = query.filter(connection_group.in_(["ready", "ping_ok_login_fail"]))
        elif connection_audit_filter == "login_ok":
            query = query.filter(connection_group == "ready")
        elif connection_audit_filter == "ping_login_fail":
            query = query.filter(connection_group == "ping_ok_login_fail")
        elif connection_audit_filter == "no_ping":
            query = query.filter(connection_group == "no_ping")

        # Dispositivos com agendamento vencido (pendentes de execucao).
        if due_filter == "1":
            now_utc = datetime.utcnow()
            query = query.join(Schedule, Schedule.device_id == Device.id).filter(
                Schedule.is_active == True,
                Schedule.next_run_at.isnot(None),
                Schedule.next_run_at <= now_utc,
            )
        
        total = query.count()
        scheduled_count = query.filter(Device.backup_scheduled == True).count()
        online_count = query.filter(Device.last_connection_status == 'online').count()
        issues_count = query.filter(Device.last_backup_status == 'failure').count()
        offline_count = query.filter(Device.last_connection_status.in_(["offline", "error"])).count()
        without_history_count = query.filter(Device.last_backup_at.is_(None)).count()
        auto_disabled_count = query.filter(Device.backup_scheduled == False).count()
        page = max(page, 1)
        per_page = max(per_page, 1)

        if sort_by == "name_desc":
            query = query.order_by(desc(Device.name))
        elif sort_by == "last_backup_desc":
            query = query.order_by(nullslast(desc(Device.last_backup_at)), asc(Device.name))
        elif sort_by == "last_backup_asc":
            query = query.order_by(asc(Device.last_backup_at), asc(Device.name))
        elif sort_by == "status_priority":
            # Prioriza equipamentos offline/falha e depois nome
            query = query.order_by(
                asc(Device.last_connection_status == "online"),
                asc(Device.last_backup_status == "success"),
                asc(Device.name),
            )
        else:
            query = query.order_by(asc(Device.name))

        items = query.offset((page - 1) * per_page).limit(per_page).all()
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "scheduled": scheduled_count,
            "online": online_count,
            "with_issues": issues_count,
            "offline": offline_count,
            "without_history": without_history_count,
            "auto_disabled": auto_disabled_count,
        }

    @staticmethod
    def get_device(db: Session, device_id: uuid.UUID) -> Optional[Device]:
        return db.query(Device).options(
            joinedload(Device.type),
            joinedload(Device.group),
            joinedload(Device.subgroup),
        ).filter(Device.id == device_id).first()

    @staticmethod
    def get_devices_by_group(db: Session, group_id: uuid.UUID) -> List[Device]:
        return db.query(Device).filter(
            Device.group_id == group_id,
            Device.is_active.isnot(False)
        ).order_by(Device.name).all()

    @staticmethod
    def get_devices_scheduled_for_backup(db: Session, tenant_id: uuid.UUID = None) -> List[Device]:
        query = db.query(Device).options(
            joinedload(Device.type),
            joinedload(Device.group),
            joinedload(Device.subgroup),
        ).filter(Device.backup_scheduled == True, Device.is_active.isnot(False))
        
        if tenant_id:
            query = query.filter(Device.tenant_id == tenant_id)
        
        return query.all()

    @staticmethod
    def update_device(db: Session, device_id: uuid.UUID, data: dict) -> Optional[Device]:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return None

        data = _sanitize_connection_fields(data, _DEVICE_CONNECTION_TEXT_FIELDS)
        for key, value in data.items():
            if key == 'password' and value:
                device.password_encrypted = encrypt_password(value)
            elif hasattr(device, key):
                setattr(device, key, value)
        
        db.commit()
        db.refresh(device)

        if device.backup_scheduled:
            DeviceService._ensure_global_daily_schedule(db, device)
        else:
            from app.models.schedule import Schedule
            schedule = db.query(Schedule).filter(Schedule.device_id == device.id).first()
            if schedule:
                schedule.is_active = False

        db.commit()
        return device

    @staticmethod
    def delete_device(db: Session, device_id: uuid.UUID) -> bool:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return False
        device.is_active = False  # Soft delete
        db.commit()
        return True


class DeviceTypeService:
    """Service for global device types (managed by Super Admin only)."""
    
    @staticmethod
    def get_all_types(db: Session, active_only: bool = True) -> List[DeviceType]:
        query = db.query(DeviceType)
        if active_only:
            query = query.filter(DeviceType.is_active == True)
        return query.order_by(DeviceType.category, DeviceType.name).all()
    
    @staticmethod
    def get_type(db: Session, type_id: uuid.UUID) -> Optional[DeviceType]:
        return db.query(DeviceType).filter(DeviceType.id == type_id).first()
    
    @staticmethod
    def get_types_by_category(db: Session) -> Dict[str, List[DeviceType]]:
        types = db.query(DeviceType).filter(DeviceType.is_active == True).order_by(DeviceType.name).all()
        result = {}
        for t in types:
            if t.category not in result:
                result[t.category] = []
            result[t.category].append(t)
        return result
    
    @staticmethod
    def create_type(db: Session, data: dict) -> DeviceType:
        device_type = DeviceType(
            name=data['name'],
            slug=data['slug'],
            description=data.get('description'),
            script_name=data['script_name'],
            required_parameters=data.get('required_parameters'),
            default_port=data.get('default_port', 22),
            use_telnet=data.get('use_telnet', False),
            category=data.get('category', 'other'),
            is_active=True
        )
        db.add(device_type)
        db.commit()
        db.refresh(device_type)
        return device_type


class DeviceGroupService:
    """Service for device groups (per tenant)."""
    
    @staticmethod
    def get_tenant_groups(db: Session, tenant_id: uuid.UUID) -> List[DeviceGroup]:
        return db.query(DeviceGroup).filter(
            DeviceGroup.tenant_id == tenant_id,
            DeviceGroup.is_active == True
        ).order_by(DeviceGroup.name).all()
    
    @staticmethod
    def get_group(db: Session, group_id: uuid.UUID) -> Optional[DeviceGroup]:
        return db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
    
    @staticmethod
    def get_groups_with_device_count(db: Session, tenant_id: uuid.UUID) -> List[Dict[str, Any]]:
        from sqlalchemy import func
        
        groups = db.query(
            DeviceGroup,
            func.count(Device.id).label('device_count')
        ).outerjoin(
            Device,
            (Device.group_id == DeviceGroup.id) & Device.is_active.isnot(False)
        ).filter(
            DeviceGroup.tenant_id == tenant_id,
            DeviceGroup.is_active == True
        ).group_by(DeviceGroup.id).order_by(DeviceGroup.name).all()
        
        return [{'group': g[0], 'device_count': g[1]} for g in groups]
    
    @staticmethod
    def create_group(db: Session, tenant_id: uuid.UUID, data: dict) -> DeviceGroup:
        normalized_slug = str((data.get('slug') or '')).strip().lower()
        if not normalized_slug:
            raise ValueError("Slug do grupo invalido.")

        data = _sanitize_connection_fields(data, _GROUP_CONNECTION_TEXT_FIELDS)
        existing = db.query(DeviceGroup).filter(
            DeviceGroup.tenant_id == tenant_id,
            DeviceGroup.slug == normalized_slug,
            DeviceGroup.is_active == True
        ).first()
        if existing:
            raise ValueError("Ja existe um grupo ativo com esse nome.")

        group = DeviceGroup(
            tenant_id=tenant_id,
            name=str(data['name']).strip(),
            slug=normalized_slug,
            description=data.get('description'),
            connection_type=data.get('connection_type', 'direct'),
            # VPN fields
            uses_vpn=data.get('uses_vpn', False),
            vpn_type=data.get('vpn_type', 'l2tp'),
            vpn_server=data.get('vpn_server'),
            vpn_username=data.get('vpn_username'),
            vpn_password_encrypted=encrypt_password(data['vpn_password']) if data.get('vpn_password') else None,
            vpn_ipsec_secret_encrypted=encrypt_password(data['vpn_ipsec_secret']) if data.get('vpn_ipsec_secret') else None,
            # Jump Host fields
            uses_jump_host=data.get('uses_jump_host', False),
            jump_host=data.get('jump_host'),
            jump_port=data.get('jump_port', 22),
            jump_username=data.get('jump_username'),
            jump_password_encrypted=encrypt_password(data['jump_password']) if data.get('jump_password') else None,
            jump_key_encrypted=encrypt_password(data['jump_key']) if data.get('jump_key') else None,
            is_active=True
        )
        db.add(group)
        db.commit()
        db.refresh(group)
        return group
    
    @staticmethod
    def update_group(db: Session, group_id: uuid.UUID, data: dict) -> Optional[DeviceGroup]:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
        if not group:
            return None

        data = _sanitize_connection_fields(data, _GROUP_CONNECTION_TEXT_FIELDS)
        for key, value in data.items():
            # Handle encrypted password fields
            if key == 'vpn_password' and value:
                group.vpn_password_encrypted = encrypt_password(value)
            elif key == 'vpn_ipsec_secret' and value:
                group.vpn_ipsec_secret_encrypted = encrypt_password(value)
            elif key == 'jump_password' and value:
                group.jump_password_encrypted = encrypt_password(value)
            elif key == 'jump_key' and value:
                group.jump_key_encrypted = encrypt_password(value)
            elif hasattr(group, key):
                setattr(group, key, value)
        
        db.commit()
        db.refresh(group)
        return group
    
    @staticmethod
    def delete_group(db: Session, group_id: uuid.UUID) -> bool:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
        if not group:
            return False
            
        device_count = db.query(Device).filter(Device.group_id == group_id).count()
        if device_count == 0:
            from app.models.device_subgroup import DeviceSubgroup
            db.query(DeviceSubgroup).filter(DeviceSubgroup.group_id == group_id).delete(synchronize_session=False)
            db.delete(group)
        else:
            group.is_active = False
            
        db.commit()
        return True
