from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

# Create blueprint
employee_bp = Blueprint('employee', __name__, template_folder='templates/employee')

# Global variables - will be set when blueprint is registered
db = None
Employee = None
EmployeePayment = None
User = None

def create_employee_models(database):
    global Employee, EmployeePayment, User
    
    class Employee(database.Model):
        __tablename__ = 'employee'
        id = database.Column(database.Integer, primary_key=True)
        username = database.Column(database.String(80), unique=True, nullable=False)
        password_hash = database.Column(database.String(120), nullable=False)
        role = database.Column(database.String(20), nullable=False, default='employee')
        status = database.Column(database.String(20), nullable=False, default='active')
        salary = database.Column(database.Float, default=0.0)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
        created_by = database.Column(database.String(80), default='admin')

    class EmployeePayment(database.Model):
        __tablename__ = 'employee_payment'
        id = database.Column(database.Integer, primary_key=True)
        employee_id = database.Column(database.Integer, database.ForeignKey('employee.id'), nullable=False)
        salary = database.Column(database.Float, nullable=False)
        status = database.Column(database.String(20), nullable=False, default='unpaid')
        paid_date = database.Column(database.DateTime)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    # Get User model from main app
    User = database.Model.registry._class_registry.get('User')
    
    return Employee, EmployeePayment, User

# Decorators
def employee_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('employee_logged_in'):
            return redirect(url_for('employee.employee_login'))
        return f(*args, **kwargs)
    return decorated_function

# Employee Routes
@employee_bp.route('/')
@employee_required
def employee_dashboard():
    users = User.query.all() if User else []
    active_users = [u for u in users if getattr(u, 'verified', True)]
    return render_template('employee_dashboard.html', 
                         users=users, 
                         active_users=active_users,
                         employee_username=session.get('employee_username'))

@employee_bp.route('/login', methods=['GET', 'POST'])
def employee_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        employee = Employee.query.filter_by(username=username).first() if Employee else None
        if employee and employee.status == 'active' and check_password_hash(employee.password_hash, password):
            session['employee_logged_in'] = True
            session['employee_username'] = username
            session['employee_id'] = employee.id
            print(f"Employee logged in: {username}")
            return redirect(url_for('employee.employee_dashboard'))
        else:
            flash('Invalid credentials or account disabled')
    
    return render_template('employee_login.html')

@employee_bp.route('/users')
@employee_required
def manage_users():
    users = User.query.all() if User else []
    return render_template('employee_manage_users.html', users=users)

@employee_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@employee_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id) if User else None
    if user:
        user.verified = not getattr(user, 'verified', True)
        db.session.commit()
        status = "activated" if user.verified else "deactivated"
        flash(f'User {user.email} {status}')
    return redirect(url_for('employee.manage_users'))

@employee_bp.route('/payments')
@employee_required
def employee_payments():
    employee_id = session.get('employee_id')
    payments = EmployeePayment.query.filter_by(employee_id=employee_id).all() if EmployeePayment else []
    return render_template('employee_payments.html', payments=payments)

@employee_bp.route('/logout')
def employee_logout():
    session.clear()
    flash('Employee logged out')
    return redirect(url_for('employee.employee_login'))

def init_employee_db(app_db):
    """Initialize employee database models"""
    global db, Employee, EmployeePayment, User
    db = app_db
    Employee, EmployeePayment, User = create_employee_models(db)
    db.create_all()