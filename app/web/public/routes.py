from flask import Blueprint, render_template

bp = Blueprint('public', __name__)

@bp.route('/')
def index():
    plans = [
        {
            'name': 'Iniciante',
            'price': 'Grátis',
            'devices': 2,
            'features': ['Backups diários', 'Retenção de 7 dias', 'Suporte via email'],
            'popular': False,
            'btn_class': 'btn-outline'
        },
        {
            'name': 'Profissional',
            'price': 'R$ 49/mês',
            'devices': 20,
            'features': ['Backups a cada hora', 'Retenção de 30 dias', 'Suporte prioritário', 'API REST'],
            'popular': True,
            'btn_class': 'btn-primary'
        },
        {
            'name': 'Enterprise',
            'price': 'Consultar',
            'devices': 'Ilimitado',
            'features': ['Personalizado', 'Retenção ilimitada', 'SLA Garantido', 'On-premise opcional'],
            'popular': False,
            'btn_class': 'btn-outline'
        }
    ]
    return render_template('public/landing.html', plans=plans)

@bp.route('/pricing')
def pricing():
    return render_template('public/pricing.html')

@bp.route('/login')
def login_redirect():
    from flask import redirect, url_for
    return redirect(url_for('auth.login'))
