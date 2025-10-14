from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import secrets
import string

# Create blueprint
mentor_bp = Blueprint('mentor', __name__)

# Import db - will be set when blueprint is registered
db = None
Mentor = None
Student = None
Coupon = None

# Models will be created when init_mentor_db is called
def create_models(database):
    global Mentor, Student, Coupon
    
    class Mentor(database.Model):
        __tablename__ = 'mentor'
        id = database.Column(database.Integer, primary_key=True)
        mentor_id = database.Column(database.String(50), unique=True, nullable=False)
        password_hash = database.Column(database.String(128), nullable=False)
        name = database.Column(database.String(100), nullable=False)
        email = database.Column(database.String(120), nullable=False)
        created_by_admin_id = database.Column(database.Integer, nullable=False)
        active = database.Column(database.Boolean, default=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    class Student(database.Model):
        __tablename__ = 'student'
        id = database.Column(database.Integer, primary_key=True)
        name = database.Column(database.String(100), nullable=False)
        email = database.Column(database.String(120), nullable=False)
        coupon_code_used = database.Column(database.String(50), nullable=True)
        registered_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    # Update existing Coupon model to include mentor_id and student_id
    class MentorCoupon(database.Model):
        __tablename__ = 'mentor_coupon'
        id = database.Column(database.Integer, primary_key=True)
        code = database.Column(database.String(50), unique=True, nullable=False)
        mentor_id = database.Column(database.Integer, nullable=True)  # Remove FK constraint to avoid conflicts
        student_id = database.Column(database.Integer, nullable=True)  # Remove FK constraint to avoid conflicts
        used_at = database.Column(database.DateTime, nullable=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
        discount_percent = database.Column(database.Integer, nullable=False, default=10)
        active = database.Column(database.Boolean, default=True)
    
    # Set global reference for easier access
    Coupon = MentorCoupon
    return Mentor, Student, MentorCoupon

# Decorators
def mentor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('mentor_logged_in'):
            return redirect(url_for('mentor.login'))
        
        # Check if mentor is still active
        mentor = Mentor.query.filter_by(mentor_id=session.get('mentor_id')).first()
        if not mentor or not mentor.active:
            session.clear()
            flash('Your mentor account has been deactivated. Please contact admin.')
            return redirect(url_for('mentor.login'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@mentor_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mentor_id = request.form['mentor_id'].strip()
        password = request.form['password'].strip()
        
        mentor = Mentor.query.filter_by(mentor_id=mentor_id).first()
        
        if mentor and mentor.active and check_password_hash(mentor.password_hash, password):
            session['mentor_logged_in'] = True
            session['mentor_id'] = mentor.mentor_id
            session['mentor_name'] = mentor.name
            flash(f'Welcome back, {mentor.name}!')
            return redirect(url_for('mentor.dashboard'))
        else:
            flash('Invalid mentor ID or password.')
    
    return render_template('mentor/mentor_login.html')

@mentor_bp.route('/dashboard')
@mentor_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    
    mentor = Mentor.query.filter_by(mentor_id=session['mentor_id']).first()
    
    # Get students who used coupons assigned to this mentor
    query = db.session.query(Student, MentorCoupon).join(
        MentorCoupon, Student.id == MentorCoupon.student_id
    ).filter(MentorCoupon.mentor_id == mentor.id)
    
    if search:
        query = query.filter(
            db.or_(
                Student.name.contains(search),
                Student.email.contains(search)
            )
        )
    
    students = query.paginate(
        page=page, per_page=10, error_out=False
    )
    
    # Get coupon statistics
    total_coupons = MentorCoupon.query.filter_by(mentor_id=mentor.id).count()
    used_coupons = MentorCoupon.query.filter_by(mentor_id=mentor.id).filter(
        MentorCoupon.used_at.isnot(None)
    ).count()
    
    return render_template('mentor/mentor_dashboard.html',
                         students=students,
                         search=search,
                         total_coupons=total_coupons,
                         used_coupons=used_coupons,
                         mentor=mentor)

@mentor_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('mentor.login'))

# Utility functions
def generate_mentor_id():
    """Generate unique mentor ID"""
    while True:
        mentor_id = 'MNT' + ''.join(secrets.choice(string.digits) for _ in range(6))
        if not Mentor.query.filter_by(mentor_id=mentor_id).first():
            return mentor_id

def generate_mentor_password():
    """Generate secure password for mentor"""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(12))

def create_simple_models(database):
    """Fallback to create simple models without relationships"""
    global Mentor, Student, MentorCoupon, Coupon
    
    class Mentor(database.Model):
        __tablename__ = 'mentor_simple'
        id = database.Column(database.Integer, primary_key=True)
        mentor_id = database.Column(database.String(50), unique=True, nullable=False)
        password_hash = database.Column(database.String(128), nullable=False)
        name = database.Column(database.String(100), nullable=False)
        email = database.Column(database.String(120), nullable=False)
        created_by_admin_id = database.Column(database.Integer, nullable=False)
        active = database.Column(database.Boolean, default=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    class Student(database.Model):
        __tablename__ = 'student_simple'
        id = database.Column(database.Integer, primary_key=True)
        name = database.Column(database.String(100), nullable=False)
        email = database.Column(database.String(120), nullable=False)
        coupon_code_used = database.Column(database.String(50), nullable=True)
        registered_at = database.Column(database.DateTime, default=datetime.utcnow)
    
    class MentorCoupon(database.Model):
        __tablename__ = 'mentor_coupon_simple'
        id = database.Column(database.Integer, primary_key=True)
        code = database.Column(database.String(50), unique=True, nullable=False)
        mentor_id = database.Column(database.Integer, nullable=True)
        student_id = database.Column(database.Integer, nullable=True)
        used_at = database.Column(database.DateTime, nullable=True)
        created_at = database.Column(database.DateTime, default=datetime.utcnow)
        discount_percent = database.Column(database.Integer, nullable=False, default=10)
        active = database.Column(database.Boolean, default=True)
    
    Coupon = MentorCoupon
    database.create_all()
    print("Simple mentor models created successfully")
    return Mentor, Student, MentorCoupon

# Initialize tables when blueprint is imported
def init_mentor_db(app_db):
    """Call this from main app after db is initialized"""
    global db, Mentor, Student, MentorCoupon, Coupon
    db = app_db
    try:
        Mentor, Student, MentorCoupon = create_models(db)
        Coupon = MentorCoupon  # Alias for compatibility
        # Tables will be created in the current app context
        db.create_all()
        print("Mentor database models created successfully")
    except Exception as e:
        print(f"Error creating mentor models: {e}")
        # Create simplified models without relationships if there are conflicts
        create_simple_models(db)