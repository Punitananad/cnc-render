from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os

# Create blueprint
admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

# Import db - will be set when blueprint is registered
db = None
AdminUser = None
Coupon = None

# Models will be created when init_admin_db is called
def create_models(database):
    global AdminUser, Coupon
    
    class AdminUser(database.Model):
        __tablename__ = 'admin_user'
        id = database.Column(database.Integer, primary_key=True)
        username = database.Column(database.String(80), unique=True, nullable=False)
        password_hash = database.Column(database.String(120), nullable=False)
        role = database.Column(database.String(20), nullable=False, default='admin')  # 'admin' or 'owner'
        created_at = database.Column(database.DateTime, default=datetime.utcnow)

    class Coupon(database.Model):
        __tablename__ = 'coupon'
        id = database.Column(database.Integer, primary_key=True)
        code = database.Column(database.String(50), unique=True, nullable=False)
        discount_percent = database.Column(database.Integer, nullable=False)
        created_by = database.Column(database.String(80), nullable=False)
        active = database.Column(database.Boolean, default=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    return AdminUser, Coupon

# TODO: Move admin password to environment variable for production
ADMIN_PASSWORD = "welcometocnt"

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_dashboard_access'):
            return redirect(url_for('admin.admin_login_panel'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@admin_bp.route('/')
@admin_required
def admin_dashboard_panel():
    from employee_blueprint import Employee, User
    users = User.query.all() if User else []
    employees = Employee.query.all() if Employee else []
    coupons = Coupon.query.all() if Coupon else []
    return render_template('admin_dashboard_panel.html', 
                         users=users,
                         employees=employees, 
                         coupons=coupons)

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login_panel():
    if request.method == 'POST':
        password = request.form['password']
        if password == ADMIN_PASSWORD:
            session['admin_dashboard_access'] = True
            session['admin_log'] = 'authenticated'
            print(f"Admin panel accessed with correct password")
            return redirect(url_for('admin.admin_dashboard_panel'))
        else:
            flash('Invalid admin password')
    
    return render_template('admin_login_panel.html')

@admin_bp.route('/create-coupon', methods=['GET', 'POST'])
@admin_required
def admin_create_coupon():
    if request.method == 'POST':
        code = request.form['code'].upper()
        discount_percent = int(request.form['discount_percent'])
        active = 'active' in request.form
        
        # Check if coupon code already exists
        existing = Coupon.query.filter_by(code=code).first()
        if existing:
            flash('Coupon code already exists')
            return render_template('admin_create_coupon.html')
        
        coupon = Coupon(
            code=code,
            discount_percent=discount_percent,
            created_by='admin',
            active=active
        )
        db.session.add(coupon)
        db.session.commit()
        
        flash(f'Coupon created: {code} ({discount_percent}%) by admin')
        return redirect(url_for('admin.admin_create_coupon'))
    
    return render_template('admin_create_coupon.html')

@admin_bp.route('/create-employee', methods=['GET', 'POST'])
@admin_required
def admin_create_employee():
    if request.method == 'POST':
        from employee_blueprint import Employee
        username = request.form['username']
        password = request.form['password']
        salary = float(request.form.get('salary', 0))
        
        # Check if username already exists
        existing = Employee.query.filter_by(username=username).first() if Employee else None
        if existing:
            flash('Employee username already exists')
            return render_template('admin_create_employee.html')
        
        employee = Employee(
            username=username,
            password_hash=generate_password_hash(password),
            role='employee',
            salary=salary,
            status='active'
        )
        db.session.add(employee)
        db.session.commit()
        
        flash(f'Employee created: {username}')
        print(f'Employee created by admin: {username}')
        return redirect(url_for('admin.admin_create_employee'))
    
    return render_template('admin_create_employee.html')

@admin_bp.route('/manage-employees')
@admin_required
def admin_manage_employees():
    from employee_blueprint import Employee
    employees = Employee.query.all() if Employee else []
    return render_template('admin_manage_employees.html', employees=employees)

@admin_bp.route('/employees/<int:employee_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_employee(employee_id):
    from employee_blueprint import Employee
    employee = Employee.query.get_or_404(employee_id) if Employee else None
    if employee:
        employee.status = 'active' if employee.status == 'disabled' else 'disabled'
        db.session.commit()
        flash(f'Employee {employee.username} {employee.status}')
    return redirect(url_for('admin.admin_manage_employees'))

@admin_bp.route('/manage-users')
@admin_required
def admin_manage_users():
    from employee_blueprint import User
    users = User.query.all() if User else []
    return render_template('admin_manage_users.html', users=users)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    from employee_blueprint import User
    user = User.query.get_or_404(user_id) if User else None
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.email} deleted')
    return redirect(url_for('admin.admin_manage_users'))

@admin_bp.route('/manage-coupons')
@admin_required
def admin_manage_coupons():
    all_coupons = Coupon.query.order_by(Coupon.created_at.desc()).all() if Coupon else []
    return render_template('admin_manage_coupons.html', coupons=all_coupons)

@admin_bp.route('/coupons/<int:coupon_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_coupon(coupon_id):
    coupon = Coupon.query.get_or_404(coupon_id)
    coupon.active = not coupon.active
    db.session.commit()
    
    status = "activated" if coupon.active else "deactivated"
    flash(f'Coupon {coupon.code} {status}')
    return redirect(url_for('admin.admin_manage_coupons'))

@admin_bp.route('/admin-logout')
def admin_logout():
    session.clear()
    flash('Admin logged out')
    return redirect(url_for('admin.admin_login_panel'))

# Initialize tables when blueprint is imported
def init_admin_db(app_db):
    """Call this from main app after db is initialized"""
    global db, AdminUser, Coupon
    db = app_db
    AdminUser, Coupon = create_models(db)
    # Tables will be created in the current app context
    db.create_all()