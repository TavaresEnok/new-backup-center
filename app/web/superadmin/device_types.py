import re
import uuid
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import func, or_

from app.core.database import SessionLocal
from app.models.device import Device
from app.models.device_type import DeviceType
from app.models.user import UserRole
from app.web.auth.decorators import login_required

bp = Blueprint('superadmin_device_types', __name__, url_prefix='/admin/device-types')


@bp.before_request
def check_superadmin():
    if session.get('user_role') != UserRole.SUPER_ADMIN.value:
        return redirect(url_for('auth.login'))


def _normalize_slug(raw: str) -> str:
    value = (raw or '').strip().lower()
    value = re.sub(r'[^a-z0-9-]+', '-', value)
    value = re.sub(r'-{2,}', '-', value).strip('-')
    return value


def _normalize_required_parameters(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    values = []
    for line in raw.replace(',', '\n').splitlines():
        item = line.strip()
        if item:
            values.append(item)
    return '\n'.join(values) if values else None


@bp.route('/')
@login_required
def list_types():
    q = (request.args.get('q') or '').strip()
    status = (request.args.get('status') or 'all').strip().lower()
    category = (request.args.get('category') or 'all').strip().lower()
    protocol = (request.args.get('protocol') or 'all').strip().lower()
    sort = (request.args.get('sort') or 'name_asc').strip().lower()

    db = SessionLocal()
    try:
        query = db.query(DeviceType)
        if q:
            term = f'%{q}%'
            query = query.filter(
                or_(
                    DeviceType.name.ilike(term),
                    DeviceType.slug.ilike(term),
                    DeviceType.script_name.ilike(term),
                    DeviceType.description.ilike(term),
                )
            )
        if status == 'active':
            query = query.filter(DeviceType.is_active.is_(True))
        elif status == 'inactive':
            query = query.filter(DeviceType.is_active.is_(False))

        if category != 'all':
            query = query.filter(func.lower(DeviceType.category) == category)

        if protocol == 'telnet':
            query = query.filter(DeviceType.use_telnet.is_(True))
        elif protocol == 'ssh':
            query = query.filter(DeviceType.use_telnet.is_(False))

        if sort == 'name_desc':
            query = query.order_by(DeviceType.name.desc())
        elif sort == 'newest':
            query = query.order_by(DeviceType.created_at.desc())
        elif sort == 'oldest':
            query = query.order_by(DeviceType.created_at.asc())
        else:
            query = query.order_by(DeviceType.name.asc())

        types = query.all()
        type_ids = [t.id for t in types]
        usage_counts = {}
        if type_ids:
            usage_counts = {
                str(type_id): int(count or 0)
                for type_id, count in db.query(Device.device_type_id, func.count(Device.id))
                .filter(Device.device_type_id.in_(type_ids))
                .group_by(Device.device_type_id)
                .all()
            }

        rows = []
        for dev_type in types:
            rows.append(
                {
                    'dev_type': dev_type,
                    'device_count': usage_counts.get(str(dev_type.id), 0),
                }
            )

        categories = [
            item[0]
            for item in db.query(DeviceType.category)
            .distinct()
            .order_by(DeviceType.category.asc())
            .all()
            if item[0]
        ]

        stats = {
            'total': db.query(func.count(DeviceType.id)).scalar() or 0,
            'active': db.query(func.count(DeviceType.id)).filter(DeviceType.is_active.is_(True)).scalar() or 0,
            'inactive': db.query(func.count(DeviceType.id)).filter(DeviceType.is_active.is_(False)).scalar() or 0,
            'in_use': db.query(func.count(func.distinct(Device.device_type_id))).filter(
                Device.device_type_id.isnot(None)
            ).scalar()
            or 0,
        }

        return render_template(
            'superadmin/device_types/list.html',
            rows=rows,
            stats=stats,
            q=q,
            status=status,
            category=category,
            protocol=protocol,
            sort=sort,
            categories=categories,
        )
    finally:
        db.close()


@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_type():
    if request.method == 'POST':
        db = SessionLocal()
        try:
            name = (request.form.get('name') or '').strip()
            slug = _normalize_slug(request.form.get('slug') or name)
            script_name = (request.form.get('script_name') or '').strip()
            category = (request.form.get('category') or 'other').strip().lower()
            if not category:
                category = 'other'
            default_port = int(request.form.get('default_port') or 22)
            required_parameters = _normalize_required_parameters(request.form.get('required_parameters'))

            if not name or not slug or not script_name:
                flash('Nome, slug e script são obrigatórios.', 'error')
                return render_template('superadmin/device_types/add.html')

            if db.query(DeviceType).filter(DeviceType.slug == slug).first():
                flash('Slug já utilizado por outro tipo.', 'error')
                return render_template('superadmin/device_types/add.html')

            if db.query(DeviceType).filter(DeviceType.name == name).first():
                flash('Nome já utilizado por outro tipo.', 'error')
                return render_template('superadmin/device_types/add.html')

            new_type = DeviceType(
                name=name,
                slug=slug,
                script_name=script_name,
                category=category,
                description=(request.form.get('description') or '').strip() or None,
                required_parameters=required_parameters,
                default_port=default_port,
                use_telnet=request.form.get('use_telnet') == 'on',
                is_active=request.form.get('is_active') == 'on',
            )
            db.add(new_type)
            db.commit()
            flash('Tipo de dispositivo criado com sucesso.', 'success')
            return redirect(url_for('superadmin_device_types.list_types'))
        except Exception as exc:
            db.rollback()
            flash(f'Erro ao criar tipo: {str(exc)}', 'error')
        finally:
            db.close()

    return render_template('superadmin/device_types/add.html')


@bp.route('/<type_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_type(type_id):
    db = SessionLocal()
    try:
        try:
            type_uuid = uuid.UUID(str(type_id))
        except Exception:
            flash('Tipo inválido.', 'error')
            return redirect(url_for('superadmin_device_types.list_types'))

        dev_type = db.query(DeviceType).filter(DeviceType.id == type_uuid).first()
        if not dev_type:
            flash('Tipo de dispositivo não encontrado.', 'error')
            return redirect(url_for('superadmin_device_types.list_types'))

        if request.method == 'POST':
            name = (request.form.get('name') or '').strip()
            slug = _normalize_slug(request.form.get('slug') or name)
            script_name = (request.form.get('script_name') or '').strip()
            if not name or not slug or not script_name:
                flash('Nome, slug e script são obrigatórios.', 'error')
                return render_template('superadmin/device_types/edit.html', dev_type=dev_type)

            slug_exists = (
                db.query(DeviceType)
                .filter(DeviceType.slug == slug, DeviceType.id != dev_type.id)
                .first()
            )
            if slug_exists:
                flash('Slug já utilizado por outro tipo.', 'error')
                return render_template('superadmin/device_types/edit.html', dev_type=dev_type)

            name_exists = (
                db.query(DeviceType)
                .filter(DeviceType.name == name, DeviceType.id != dev_type.id)
                .first()
            )
            if name_exists:
                flash('Nome já utilizado por outro tipo.', 'error')
                return render_template('superadmin/device_types/edit.html', dev_type=dev_type)

            dev_type.name = name
            dev_type.slug = slug
            dev_type.script_name = script_name
            dev_type.category = (request.form.get('category') or 'other').strip().lower() or 'other'
            dev_type.description = (request.form.get('description') or '').strip() or None
            dev_type.required_parameters = _normalize_required_parameters(request.form.get('required_parameters'))
            dev_type.default_port = int(request.form.get('default_port') or 22)
            dev_type.use_telnet = request.form.get('use_telnet') == 'on'
            dev_type.is_active = request.form.get('is_active') == 'on'

            db.commit()
            flash('Tipo atualizado com sucesso.', 'success')
            return redirect(url_for('superadmin_device_types.list_types'))

        return render_template('superadmin/device_types/edit.html', dev_type=dev_type)
    except Exception as exc:
        db.rollback()
        flash(f'Erro ao editar tipo: {str(exc)}', 'error')
        return redirect(url_for('superadmin_device_types.list_types'))
    finally:
        db.close()
