from flask import Blueprint, render_template, request, jsonify, abort, flash, session, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import json

# Create blueprint
employee_dashboard_bp = Blueprint('employee_dashboard', __name__, url_prefix='/employee', template_folder='templates/employee_dashboard')

# Global variables - set when blueprint is registered
db = None
User = None
EmployeeDashboard = None
Role = None
AuditLog = None
UserSession = None

def create_employee_dashboard_models(database):
    global User, EmployeeDashboard, Role, AuditLog, UserSession
    
    class Role(database.Model):
        __tablename__ = 'emp_role'
        id = database.Column(database.Integer, primary_key=True)
        name = database.Column(database.String(50), unique=True, nullable=False)  # owner, admin, employee, user
        description = database.Column(database.String(200))
        created_at = database.Column(database.DateTime, default=datetime.utcnow)

    class EmployeeDashboard(database.Model):
        __tablename__ = 'emp_dashboard_employee'
        id = database.Column(database.Integer, primary_key=True)
        full_name = database.Column(database.String(100), nullable=False)
        email = database.Column(database.String(120), unique=True, nullable=False)
        phone = database.Column(database.String(20))
        password_hash = database.Column(database.String(255), nullable=False)
        role_id = database.Column(database.Integer, database.ForeignKey('emp_role.id'), nullable=False)
        manager_id = database.Column(database.Integer, database.ForeignKey('emp_dashboard_employee.id'))
        is_active = database.Column(database.Boolean, default=True)
        can_login = database.Column(database.Boolean, default=True)
        last_login = database.Column(database.DateTime)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
        
        role = database.relationship('Role', backref='employees')
        manager = database.relationship('EmployeeDashboard', remote_side=[id], backref='subordinates')

    class AuditLog(database.Model):
        __tablename__ = 'emp_audit_log'
        id = database.Column(database.Integer, primary_key=True)
        actor_id = database.Column(database.Integer, database.ForeignKey('emp_dashboard_employee.id'), nullable=False)
        action = database.Column(database.String(100), nullable=False)
        target_type = database.Column(database.String(50), nullable=False)
        target_id = database.Column(database.Integer, nullable=False)
        meta = database.Column(database.JSON)
        ip_address = database.Column(database.String(45))
        timestamp = database.Column(database.DateTime, default=datetime.utcnow)
        
        actor = database.relationship('EmployeeDashboard', backref='audit_logs')

    class UserSession(database.Model):
        __tablename__ = 'emp_user_session'
        id = database.Column(database.Integer, primary_key=True)
        user_id = database.Column(database.Integer, database.ForeignKey('user.id'), nullable=False)
        session_token = database.Column(database.String(255), unique=True, nullable=False)
        ip_address = database.Column(database.String(45))
        user_agent = database.Column(database.String(500))
        is_active = database.Column(database.Boolean, default=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
        last_activity = database.Column(database.DateTime, default=datetime.utcnow)
    
    # Get existing User model
    try:
        from app import User as AppUser
        User = AppUser
    except:
        User = None
    
    return User, EmployeeDashboard, Role, AuditLog, UserSession

# Rate limiting storage (in production, use Redis)
rate_limit_store = {}

def check_rate_limit(employee_id, action, limit=30, window=60):
    """Check if employee has exceeded rate limit"""
    now = datetime.utcnow()
    key = f"{employee_id}:{action}"
    
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    # Clean old entries
    rate_limit_store[key] = [
        timestamp for timestamp in rate_limit_store[key]
        if now - timestamp < timedelta(seconds=window)
    ]
    
    if len(rate_limit_store[key]) >= limit:
        return False
    
    rate_limit_store[key].append(now)
    return True

def require_employee_role(*roles):
    """Decorator to check employee role permissions"""
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('employee_logged_in'):
                return jsonify({'error': 'Authentication required'}), 401
            
            employee_id = session.get('employee_id')
            employee = Employee.query.get(employee_id) if Employee else None
            
            if not employee or not employee.is_active or not employee.can_login:
                return jsonify({'error': 'Account disabled'}), 403
            
            if employee.role.name not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return wrapped
    return wrapper

def log_audit(action, target_type, target_id, meta=None):
    """Log employee action to audit trail"""
    if not session.get('employee_id'):
        return
    
    audit = AuditLog(
        actor_id=session.get('employee_id'),
        action=action,
        target_type=target_type,
        target_id=target_id,
        meta=meta or {},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

# Authentication Routes
@employee_dashboard_bp.route('/login', methods=['GET', 'POST'])
def employee_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        employee = EmployeeDashboard.query.filter_by(email=email).first() if EmployeeDashboard else None
        
        if employee and employee.is_active and employee.can_login and \
           check_password_hash(employee.password_hash, password):
            
            session['employee_logged_in'] = True
            session['employee_id'] = employee.id
            session['employee_name'] = employee.full_name
            session['employee_role'] = employee.role.name
            
            employee.last_login = datetime.utcnow()
            db.session.commit()
            
            log_audit('employee_login', 'employee', employee.id)
            return redirect(url_for('employee_dashboard.dashboard'))
        else:
            flash('Invalid credentials or account disabled', 'error')
    
    return render_template('employee_login.html')

@employee_dashboard_bp.route('/logout')
def employee_logout():
    if session.get('employee_id'):
        log_audit('employee_logout', 'employee', session.get('employee_id'))
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('employee_dashboard.employee_login'))

# Dashboard Routes
@employee_dashboard_bp.route('/')
@require_employee_role('employee', 'admin', 'owner')
def dashboard():
    total_users = User.query.count() if User else 0
    active_users = User.query.filter_by(verified=True).count() if User else 0
    active_sessions = UserSession.query.filter_by(is_active=True).count() if UserSession else 0
    recent_audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all() if AuditLog else []
    
    return render_template('employee_dashboard.html',
                         total_users=total_users,
                         active_users=active_users,
                         active_sessions=active_sessions,
                         recent_audits=recent_audits)

@employee_dashboard_bp.route('/users')
@require_employee_role('employee', 'admin', 'owner')
def users_list():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '')
    
    query = User.query if User else None
    if query and search:
        query = query.filter(User.email.ilike(f'%{search}%'))
    
    users = query.paginate(page=page, per_page=25, error_out=False) if query else None
    
    return render_template('employee_users.html', users=users, search=search)

@employee_dashboard_bp.route('/user/<int:user_id>')
@require_employee_role('employee', 'admin', 'owner')
def user_detail(user_id):
    user = User.query.get_or_404(user_id) if User else None
    user_sessions = UserSession.query.filter_by(user_id=user_id).order_by(UserSession.last_activity.desc()).limit(5).all() if UserSession else []
    
    return render_template('employee_user_detail.html', user=user, sessions=user_sessions)

# AJAX API Routes
@employee_dashboard_bp.route('/api/user/<int:user_id>/toggle', methods=['POST'])
@require_employee_role('employee', 'admin', 'owner')
def api_toggle_user(user_id):
    if not check_rate_limit(session.get('employee_id'), 'toggle_user'):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    user = User.query.get_or_404(user_id) if User else None
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent modifying owner accounts
    if hasattr(user, 'role') and user.role == 'owner':
        return jsonify({'error': 'Cannot modify owner account'}), 403
    
    user.verified = not user.verified
    db.session.commit()
    
    log_audit('toggle_user_status', 'user', user_id, {
        'new_status': user.verified,
        'user_email': user.email
    })
    
    return jsonify({
        'success': True,
        'is_active': user.verified,
        'message': f'User {"activated" if user.verified else "deactivated"}'
    })

@employee_dashboard_bp.route('/api/user/<int:user_id>/disable-login', methods=['POST'])
@require_employee_role('employee', 'admin', 'owner')
def api_disable_login(user_id):
    if not check_rate_limit(session.get('employee_id'), 'disable_login'):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    user = User.query.get_or_404(user_id) if User else None
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Add can_login field if it doesn't exist
    if not hasattr(user, 'can_login'):
        # This would require a migration in production
        pass
    
    # For now, use verified field as proxy for can_login
    user.verified = False
    db.session.commit()
    
    log_audit('disable_user_login', 'user', user_id, {
        'user_email': user.email
    })
    
    return jsonify({
        'success': True,
        'message': 'User login disabled'
    })

@employee_dashboard_bp.route('/sessions')
@require_employee_role('employee', 'admin', 'owner')
def active_sessions():
    sessions = UserSession.query.filter_by(is_active=True).order_by(UserSession.last_activity.desc()).all() if UserSession else []
    return render_template('employee_sessions.html', sessions=sessions)

@employee_dashboard_bp.route('/audit')
@require_employee_role('admin', 'owner')  # Only admin and owner can view full audit
def audit_log():
    page = request.args.get('page', 1, type=int)
    actor_filter = request.args.get('actor', '')
    action_filter = request.args.get('action', '')
    
    query = AuditLog.query if AuditLog else None
    if query:
        if actor_filter:
            query = query.join(Employee).filter(Employee.full_name.ilike(f'%{actor_filter}%'))
        if action_filter:
            query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
        
        audits = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)
    else:
        audits = None
    
    return render_template('employee_audit.html', audits=audits, actor_filter=actor_filter, action_filter=action_filter)

def init_employee_dashboard_db(app_db):
    """Initialize employee dashboard database models"""
    global db, User, EmployeeDashboard, Role, AuditLog, UserSession
    db = app_db
    User, EmployeeDashboard, Role, AuditLog, UserSession = create_employee_dashboard_models(db)
    
    # Create tables (already in app context)
    db.create_all()
    
    # Create default roles if they don't exist
    if Role.query.count() == 0:
        roles = [
            Role(name='owner', description='System Owner - Full Access'),
            Role(name='admin', description='Administrator - Manage Employees & Users'),
            Role(name='employee', description='Employee - User Management Only'),
            Role(name='user', description='Regular User')
        ]
        for role in roles:
            db.session.add(role)
        db.session.commit()
        print("Default roles created")