import unittest
import tempfile
import os
from app import app, db
from mentor import init_mentor_db, Mentor, Student, MentorCoupon
from werkzeug.security import generate_password_hash

class MentorTestCase(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        
        self.app = app.test_client()
        
        with app.app_context():
            db.create_all()
            init_mentor_db(db)
            
            # Create test mentor
            self.test_mentor = Mentor(
                mentor_id='MNT123456',
                password_hash=generate_password_hash('testpass123'),
                name='Test Mentor',
                email='mentor@test.com',
                created_by_admin_id=1,
                active=True
            )
            db.session.add(self.test_mentor)
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with app.app_context():
            db.session.remove()
            db.drop_all()
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])
    
    def test_mentor_login_success(self):
        """Test successful mentor login"""
        response = self.app.post('/mentor/login', data={
            'mentor_id': 'MNT123456',
            'password': 'testpass123'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome back, Test Mentor!', response.data)
    
    def test_mentor_login_invalid_credentials(self):
        """Test mentor login with invalid credentials"""
        response = self.app.post('/mentor/login', data={
            'mentor_id': 'MNT123456',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid mentor ID or password', response.data)
    
    def test_mentor_login_inactive_account(self):
        """Test mentor login with inactive account"""
        with app.app_context():
            mentor = Mentor.query.filter_by(mentor_id='MNT123456').first()
            mentor.active = False
            db.session.commit()
        
        response = self.app.post('/mentor/login', data={
            'mentor_id': 'MNT123456',
            'password': 'testpass123'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid mentor ID or password', response.data)
    
    def test_mentor_dashboard_access_without_login(self):
        """Test accessing mentor dashboard without login"""
        response = self.app.get('/mentor/dashboard')
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_mentor_dashboard_access_with_login(self):
        """Test accessing mentor dashboard with valid login"""
        # Login first
        with self.app.session_transaction() as sess:
            sess['mentor_logged_in'] = True
            sess['mentor_id'] = 'MNT123456'
            sess['mentor_name'] = 'Test Mentor'
        
        response = self.app.get('/mentor/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Mentor Dashboard', response.data)
    
    def test_mentor_logout(self):
        """Test mentor logout"""
        # Login first
        with self.app.session_transaction() as sess:
            sess['mentor_logged_in'] = True
            sess['mentor_id'] = 'MNT123456'
        
        response = self.app.get('/mentor/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have been logged out', response.data)
    
    def test_mentor_dashboard_with_students(self):
        """Test mentor dashboard showing students"""
        with app.app_context():
            # Create test student and coupon
            student = Student(
                name='Test Student',
                email='student@test.com',
                coupon_code_used='TESTCOUPON'
            )
            db.session.add(student)
            db.session.flush()
            
            coupon = MentorCoupon(
                code='TESTCOUPON',
                mentor_id=self.test_mentor.id,
                student_id=student.id,
                discount_percent=10,
                active=True
            )
            db.session.add(coupon)
            db.session.commit()
        
        # Login and access dashboard
        with self.app.session_transaction() as sess:
            sess['mentor_logged_in'] = True
            sess['mentor_id'] = 'MNT123456'
            sess['mentor_name'] = 'Test Mentor'
        
        response = self.app.get('/mentor/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Student', response.data)
        self.assertIn(b'TESTCOUPON', response.data)

if __name__ == '__main__':
    unittest.main()