from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os
import secrets
import hashlib
from datetime import timedelta

# Create blueprint
admin_bp = Blueprint('admin', __name__)

# Import db - will be set when blueprint is registered
db = None
AdminUser = None
Coupon = None
AdminOTP = None

# Models will be created when init_admin_db is called
def create_models(database):
    global AdminUser, Coupon, AdminOTP
    
    class AdminUser(database.Model):
        __tablename__ = 'admin_user'
        id = database.Column(database.Integer, primary_key=True)
        username = database.Column(database.String(80), unique=True, nullable=False)
        password_hash = database.Column(database.String(120), nullable=False)
        role = database.Column(database.String(20), nullable=False, default='admin')
        created_at = database.Column(database.DateTime, default=datetime.utcnow)

    class Coupon(database.Model):
        __tablename__ = 'coupon'
        id = database.Column(database.Integer, primary_key=True)
        code = database.Column(database.String(50), unique=True, nullable=False)
        discount_percent = database.Column(database.Integer, nullable=False)
        created_by = database.Column(database.String(80), nullable=False)
        active = database.Column(database.Boolean, default=True)
        mentor_id = database.Column(database.Integer, nullable=True)  # For mentor assignment
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    class AdminOTP(database.Model):
        __tablename__ = 'admin_otp'
        id = database.Column(database.Integer, primary_key=True)
        otp_hash = database.Column(database.String(128), nullable=False)
        salt = database.Column(database.String(64), nullable=False)
        expires_at = database.Column(database.DateTime, nullable=False)
        used = database.Column(database.Boolean, default=False)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    return AdminUser, Coupon, AdminOTP

# Admin credentials
ADMIN_PASSWORD = "welcometocnt"
ADMIN_EMAIL = "punitanand571@gmail.com"

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@admin_bp.route('/')
def admin_root():
    """Root admin route - redirect to login if not authenticated, dashboard if authenticated"""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin.dashboard'))
    else:
        return redirect(url_for('admin.login'))

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    try:
        # Simple count query to avoid model conflicts
        from sqlalchemy import text
        result = db.session.execute(text("SELECT COUNT(*) FROM user")).fetchone()
        user_count = result[0] if result else 0
        users = []  # Don't load all users for dashboard, just count
        print(f"Dashboard: Found {user_count} users")
    except Exception as e:
        print(f"Error fetching user count in dashboard: {e}")
        users = []
        user_count = 0
    
    try:
        import employee_dashboard_bp
        if hasattr(employee_dashboard_bp, 'EmployeeDashboard') and employee_dashboard_bp.EmployeeDashboard:
            employees = employee_dashboard_bp.EmployeeDashboard.query.all()
            employee_count = len(employees)
        else:
            employees = []
            employee_count = 0
    except:
        employees = []
        employee_count = 0
    
    try:
        import mentor
        if hasattr(mentor, 'Mentor') and mentor.Mentor:
            mentors = mentor.Mentor.query.all()
            mentor_count = len(mentors)
        else:
            mentors = []
            mentor_count = 0
    except Exception as e:
        print(f"Error fetching mentors in dashboard: {e}")
        mentors = []
        mentor_count = 0
    
    try:
        # Use direct SQL query to avoid model conflicts
        from sqlalchemy import text
        result = db.session.execute(text("SELECT COUNT(*) FROM coupon")).fetchone()
        coupon_count = result[0] if result else 0
        coupons = []
    except Exception as e:
        print(f"Error fetching coupon count: {e}")
        coupons = []
        coupon_count = 0
    admin_count = AdminUser.query.count() if AdminUser else 0
    
    return render_template('admin/dashboard.html', 
                         users=users,
                         employees=employees,
                         mentors=mentors,
                         coupons=coupons,
                         user_count=user_count,
                         employee_count=employee_count,
                         mentor_count=mentor_count,
                         coupon_count=coupon_count,
                         admin_count=admin_count)

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        
        if password == ADMIN_PASSWORD:
            # Send OTP to admin email
            send_admin_otp()
            session['admin_password_verified'] = True
            flash('OTP sent to admin email. Please check your email.')
            return redirect(url_for('admin.verify_otp'))
        else:
            flash('Invalid admin password')
    
    return render_template('admin/login.html')



@admin_bp.route('/create-employee', methods=['GET', 'POST'])
@admin_required
def admin_create_employee():
    if request.method == 'POST':
        try:
            # Import employee dashboard blueprint
            import employee_dashboard_bp
            if hasattr(employee_dashboard_bp, 'EmployeeDashboard') and employee_dashboard_bp.EmployeeDashboard:
                username = request.form['username']
                password = request.form['password']
                full_name = request.form['full_name']
                
                existing = employee_dashboard_bp.EmployeeDashboard.query.filter_by(username=username).first()
                if existing:
                    flash('Employee username already exists')
                    return render_template('admin/admin_create_employee.html')
                
                # Get employee role (assuming role_id 3 is for employees)
                employee_role = employee_dashboard_bp.EmpRole.query.filter_by(name='employee').first()
                if not employee_role:
                    flash('Employee role not found')
                    return render_template('admin/admin_create_employee.html')
                
                employee = employee_dashboard_bp.EmployeeDashboard(
                    username=username,
                    full_name=full_name,
                    password_hash=generate_password_hash(password),
                    role_id=employee_role.id,
                    is_active=True,
                    can_login=True,
                    created_by='admin'
                )
                db.session.add(employee)
                db.session.commit()
                
                flash(f'Employee created: {username}')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Employee model not available')
        except Exception as e:
            flash(f'Error creating employee: {str(e)}')
    
    return render_template('admin/admin_create_employee.html')











@admin_bp.route('/coupons/<int:coupon_id>/toggle', methods=['POST'])
@admin_required
def toggle_coupon(coupon_id):
    try:
        # Get current coupon status
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT active, code FROM coupon WHERE id = :coupon_id"), {'coupon_id': coupon_id}
        ).fetchone()
        
        if result:
            current_active = bool(result[0])
            code = result[1]
            new_active = not current_active
            
            # Update coupon status
            from sqlalchemy import text
            db.session.execute(
                text("UPDATE coupon SET active = :active WHERE id = :coupon_id"), 
                {'active': new_active, 'coupon_id': coupon_id}
            )
            db.session.commit()
            
            status = "activated" if new_active else "deactivated"
            flash(f'Coupon {code} {status}')
        else:
            flash('Coupon not found')
    except Exception as e:
        flash(f'Error updating coupon: {str(e)}')
    
    return redirect(url_for('admin.coupons'))

# Mentor Management Routes
@admin_bp.route('/mentors')
@admin_required
def mentors():
    try:
        import mentor
        if hasattr(mentor, 'Mentor') and mentor.Mentor:
            all_mentors = mentor.Mentor.query.order_by(mentor.Mentor.created_at.desc()).all()
        else:
            all_mentors = []
    except Exception as e:
        print(f"Error fetching mentors: {e}")
        all_mentors = []
    return render_template('admin/mentors.html', mentors=all_mentors)

@admin_bp.route('/create-mentor', methods=['GET', 'POST'])
@admin_required
def create_mentor():
    if request.method == 'POST':
        try:
            # Import mentor functions and check if db is initialized
            from mentor import generate_mentor_id, generate_mentor_password
            
            if not db:
                flash('Database not initialized. Please contact administrator.')
                return render_template('admin/create_mentor.html')
            
            # Import mentor model from mentor module
            import mentor
            if not hasattr(mentor, 'Mentor') or not mentor.Mentor:
                flash('Mentor model not available. Please contact administrator.')
                return render_template('admin/create_mentor.html')
            
            name = request.form['name'].strip()
            email = request.form['email'].strip()
            
            # Generate unique mentor ID and password
            mentor_id = generate_mentor_id()
            password = generate_mentor_password()
            
            new_mentor = mentor.Mentor(
                mentor_id=mentor_id,
                password_hash=generate_password_hash(password),
                name=name,
                email=email,
                created_by_admin_id=1,  # Assuming admin ID 1
                active=True
            )
            
            db.session.add(new_mentor)
            db.session.commit()
            
            # Show generated credentials once
            flash(f'Mentor created successfully! Mentor ID: {mentor_id}, Password: {password} (Save this - it won\'t be shown again!)')
            return redirect(url_for('admin.mentors'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating mentor: {str(e)}')
    
    return render_template('admin/create_mentor.html')

@admin_bp.route('/mentor/<int:mentor_id>/reset-password', methods=['POST'])
@admin_required
def reset_mentor_password(mentor_id):
    try:
        from mentor import generate_mentor_password
        import mentor
        
        if not hasattr(mentor, 'Mentor') or not mentor.Mentor:
            flash('Mentor model not available')
            return redirect(url_for('admin.mentors'))
        
        mentor_obj = mentor.Mentor.query.get_or_404(mentor_id)
        new_password = generate_mentor_password()
        mentor_obj.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        
        flash(f'Password reset for {mentor_obj.name}. New password: {new_password} (Save this - it won\'t be shown again!)')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting password: {str(e)}')
    
    return redirect(url_for('admin.mentors'))

@admin_bp.route('/mentor/<int:mentor_id>/toggle', methods=['POST'])
@admin_required
def toggle_mentor(mentor_id):
    try:
        import mentor
        
        if not hasattr(mentor, 'Mentor') or not mentor.Mentor:
            flash('Mentor model not available')
            return redirect(url_for('admin.mentors'))
        
        mentor_obj = mentor.Mentor.query.get_or_404(mentor_id)
        mentor_obj.active = not mentor_obj.active
        db.session.commit()
        
        status = "activated" if mentor_obj.active else "deactivated"
        flash(f'Mentor {mentor_obj.name} {status}')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating mentor: {str(e)}')
    
    return redirect(url_for('admin.mentors'))

@admin_bp.route('/assign-coupon-to-mentor', methods=['GET', 'POST'])
@admin_required
def assign_coupon_to_mentor():
    if request.method == 'POST':
        try:
            coupon_id = request.form['coupon_id']
            mentor_id = request.form['mentor_id']
            
            # Get coupon and mentor info
            from sqlalchemy import text
            coupon_result = db.session.execute(
                text("SELECT code FROM coupon WHERE id = :coupon_id"), {'coupon_id': coupon_id}
            ).fetchone()
            
            mentor_result = db.session.execute(
                text("SELECT name FROM mentor WHERE id = :mentor_id"), {'mentor_id': mentor_id}
            ).fetchone()
            
            if coupon_result and mentor_result:
                # Update coupon with mentor_id
                from sqlalchemy import text
                db.session.execute(
                    text("UPDATE coupon SET mentor_id = :mentor_id WHERE id = :coupon_id"), 
                    {'mentor_id': mentor_id, 'coupon_id': coupon_id}
                )
                db.session.commit()
                
                flash(f'Coupon {coupon_result[0]} assigned to mentor {mentor_result[0]}')
                return redirect(url_for('admin.coupons'))
            else:
                flash('Coupon or mentor not found')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error assigning coupon: {str(e)}')
    
    try:
        # Get active mentors
        from sqlalchemy import text
        mentor_result = db.session.execute(
            text("SELECT id, name FROM mentor WHERE active = 1")
        )
        mentors = [{'id': row[0], 'name': row[1]} for row in mentor_result]
        
        # Get unassigned active coupons
        coupon_result = db.session.execute(
            text("SELECT id, code FROM coupon WHERE active = 1 AND (mentor_id IS NULL OR mentor_id = '')")
        )
        coupons = [{'id': row[0], 'code': row[1]} for row in coupon_result]
        
    except Exception as e:
        print(f"Error fetching mentors/coupons: {e}")
        mentors = []
        coupons = []
    
    return render_template('admin/assign_coupon.html', mentors=mentors, coupons=coupons)

# Employee Management Routes
@admin_bp.route('/employees')
@admin_required
def employees():
    try:
        # Import the employee dashboard blueprint to get the EmployeeDashboard model
        import employee_dashboard_bp
        if hasattr(employee_dashboard_bp, 'EmployeeDashboard') and employee_dashboard_bp.EmployeeDashboard:
            all_employees = employee_dashboard_bp.EmployeeDashboard.query.order_by(employee_dashboard_bp.EmployeeDashboard.created_at.desc()).all()
        else:
            all_employees = []
    except Exception as e:
        print(f"Error fetching employees: {e}")
        all_employees = []
    return render_template('admin/employees.html', employees=all_employees)

@admin_bp.route('/employee/<int:employee_id>/toggle', methods=['POST'])
@admin_required
def toggle_employee(employee_id):
    try:
        import employee_dashboard_bp
        if hasattr(employee_dashboard_bp, 'EmployeeDashboard') and employee_dashboard_bp.EmployeeDashboard:
            employee = employee_dashboard_bp.EmployeeDashboard.query.get_or_404(employee_id)
            employee.is_active = not employee.is_active
            db.session.commit()
            status = 'active' if employee.is_active else 'inactive'
            flash(f'Employee {employee.username} {status}')
        else:
            flash('Employee model not available')
    except Exception as e:
        flash(f'Error updating employee: {str(e)}')
    
    return redirect(url_for('admin.employees'))

@admin_bp.route('/employee/<int:employee_id>/delete', methods=['POST'])
@admin_required
def delete_employee(employee_id):
    try:
        import employee_dashboard_bp
        if hasattr(employee_dashboard_bp, 'EmployeeDashboard') and employee_dashboard_bp.EmployeeDashboard:
            employee = employee_dashboard_bp.EmployeeDashboard.query.get_or_404(employee_id)
            username = employee.username
            
            # Delete related audit logs first to avoid foreign key constraint
            if hasattr(employee_dashboard_bp, 'AuditLog') and employee_dashboard_bp.AuditLog:
                employee_dashboard_bp.AuditLog.query.filter_by(actor_id=employee_id).delete()
            
            db.session.delete(employee)
            db.session.commit()
            flash(f'Employee {username} deleted successfully')
        else:
            flash('Employee model not available')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting employee: {str(e)}')
    
    return redirect(url_for('admin.employees'))

def send_admin_otp():
    """Send OTP to admin email using the same method as main app"""
    try:
        # Clear any existing unused OTPs
        AdminOTP.query.filter_by(used=False).delete()
        db.session.commit()
        
        # Generate OTP
        otp = f"{secrets.randbelow(1_000_000):06d}"
        salt = os.urandom(16)
        otp_hash = hashlib.sha256(salt + otp.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        
        # Save OTP to database
        admin_otp = AdminOTP(
            otp_hash=otp_hash,
            salt=salt.hex(),
            expires_at=expires_at
        )
        db.session.add(admin_otp)
        db.session.commit()
        
        # Import and use the exact same email setup as main app
        from flask_mail import Mail, Message
        from flask import current_app
        
        # Get mail instance from current app
        mail = Mail(current_app)
        
        subject = "Admin Login OTP - CalculatenTrade"
        html = f"""
        <h2>Admin Login OTP</h2>
        <p>Your OTP for admin login is:</p>
        <h1 style="color: #007bff; letter-spacing: 3px;">{otp}</h1>
        <p>This OTP will expire in 5 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        """
        
        # Create and send message using the same method as main app
        msg = Message(subject=subject, recipients=[ADMIN_EMAIL], html=html)
        mail.send(msg)
        print(f"Admin OTP sent to {ADMIN_EMAIL}: {otp}")
        
    except Exception as e:
        print(f"Error sending admin OTP: {e}")
        import traceback
        traceback.print_exc()

@admin_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if not session.get('admin_password_verified'):
        return redirect(url_for('admin.login'))
    
    if request.method == 'POST':
        otp_input = request.form['otp']
        
        # Get latest unused OTP
        admin_otp = AdminOTP.query.filter_by(used=False).order_by(AdminOTP.id.desc()).first()
        
        if not admin_otp:
            flash('No valid OTP found. Please login again.')
            return redirect(url_for('admin.login'))
        
        if datetime.utcnow() > admin_otp.expires_at:
            flash('OTP expired. Please login again.')
            return redirect(url_for('admin.login'))
        
        # Verify OTP
        salt = bytes.fromhex(admin_otp.salt)
        calculated_hash = hashlib.sha256(salt + otp_input.encode()).hexdigest()
        
        if calculated_hash == admin_otp.otp_hash:
            # Mark OTP as used
            admin_otp.used = True
            db.session.commit()
            
            # Set admin session
            session.clear()
            session['admin_logged_in'] = True
            session['admin_username'] = 'admin'
            session['admin_role'] = 'owner'
            
            flash('Admin login successful!')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid OTP. Please try again.')
    
    return render_template('admin/admin_verify_otp.html')

@admin_bp.route('/logout')
def logout():
    session.clear()
    flash('Admin logged out')
    return redirect(url_for('admin.login'))

@admin_bp.route('/coupons')
@admin_required
def coupons():
    try:
        # Use direct SQL query to avoid model conflicts
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT id, code, discount_percent, created_by, active, mentor_id, created_at FROM coupon ORDER BY created_at DESC")
        )
        
        all_coupons = []
        for row in result:
            coupon_dict = {
                'id': row[0],
                'code': row[1],
                'discount_percent': row[2],
                'created_by': row[3],
                'active': bool(row[4]),
                'mentor_id': row[5],
                'created_at': row[6]
            }
            all_coupons.append(coupon_dict)
    except Exception as e:
        print(f"Error fetching coupons: {e}")
        all_coupons = []
    
    return render_template('admin/coupons.html', coupons=all_coupons)

@admin_bp.route('/create-coupon', methods=['GET', 'POST'])
@admin_required
def create_coupon():
    if request.method == 'POST':
        code = request.form['code'].upper()
        discount_percent = int(request.form['discount_percent'])
        active = 'active' in request.form
        
        # Check if coupon exists
        from sqlalchemy import text
        existing = db.session.execute(
            text("SELECT id FROM coupon WHERE code = :code"), {'code': code}
        ).fetchone()
        
        if existing:
            flash('Coupon code already exists')
            return render_template('admin/create_coupon.html')
        
        # Insert new coupon
        from sqlalchemy import text
        db.session.execute(
            text("INSERT INTO coupon (code, discount_percent, created_by, active, created_at) VALUES (:code, :discount, :created_by, :active, :created_at)"),
            {
                'code': code,
                'discount': discount_percent,
                'created_by': session.get('admin_username', 'admin'),
                'active': active,
                'created_at': datetime.utcnow()
            }
        )
        db.session.commit()
        
        flash(f'Coupon created: {code} ({discount_percent}%)')
        return redirect(url_for('admin.coupons'))
    
    return render_template('admin/create_coupon.html')

@admin_bp.route('/create-user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if session.get('admin_role') != 'owner':
        flash('Access denied. Owner privileges required.')
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'admin')
        
        existing = AdminUser.query.filter_by(username=username).first() if AdminUser else None
        if existing:
            flash('Username already exists')
            return render_template('admin/create_user.html')
        
        admin_user = AdminUser(
            username=username,
            password_hash=generate_password_hash(password),
            role=role
        )
        db.session.add(admin_user)
        db.session.commit()
        
        flash(f'Admin user created: {username}')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('admin/create_user.html')

@admin_bp.route('/users')
@admin_required
def users():
    try:
        # Simple direct query using raw SQL to avoid model conflicts
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT id, email, name, verified, google_id, subscription_active, subscription_type, subscription_expires, registered_on FROM user ORDER BY registered_on DESC")
        )
        
        # Convert to list of dictionaries
        all_users = []
        for row in result:
            user_dict = {
                'id': row[0],
                'email': row[1],
                'name': row[2],
                'verified': bool(row[3]),
                'google_id': row[4],
                'subscription_active': bool(row[5]),
                'subscription_type': row[6],
                'subscription_expires': row[7],
                'registered_on': row[8]
            }
            all_users.append(user_dict)
        
        print(f"Found {len(all_users)} users in database")
            
    except Exception as e:
        print(f"Error fetching users: {e}")
        import traceback
        traceback.print_exc()
        all_users = []
    
    return render_template('admin/users.html', users=all_users)

@admin_bp.route('/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    try:
        # Get current user status
        from sqlalchemy import text
        result = db.session.execute(
            text("SELECT verified, email FROM user WHERE id = :user_id"), {'user_id': user_id}
        ).fetchone()
        
        if result:
            current_verified = bool(result[0])
            email = result[1]
            new_verified = not current_verified
            
            # Update user status
            from sqlalchemy import text
            db.session.execute(
                text("UPDATE user SET verified = :verified WHERE id = :user_id"), 
                {'verified': new_verified, 'user_id': user_id}
            )
            db.session.commit()
            
            status = "activated" if new_verified else "deactivated"
            flash(f'User {email} {status}')
        else:
            flash('User not found')
    except Exception as e:
        flash(f'Error updating user: {str(e)}')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/owner-password', methods=['GET', 'POST'])
@admin_required
def owner_password():
    if session.get('admin_role') != 'owner':
        flash('Access denied. Owner privileges required.')
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        # This would update owner password - implement as needed
        flash('Owner password updated')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('admin/owner_password.html')

# Initialize tables when blueprint is imported
def init_admin_db(app_db):
    """Call this from main app after db is initialized"""
    global db, AdminUser, Coupon, AdminOTP
    db = app_db
    AdminUser, Coupon, AdminOTP = create_models(db)
    # Tables will be created in the current app context
    db.create_all()