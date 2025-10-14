# Mentor System Integration Instructions

## 1. Register Mentor Blueprint in app.py

Add the following lines to your `app.py` file after the existing blueprint registrations:

```python
# Register mentor blueprint
from mentor import mentor_bp, init_mentor_db
app.register_blueprint(mentor_bp, url_prefix='/mentor')
```

## 2. Initialize Mentor Database

In your `app.py` file, in the `if __name__ == "__main__":` section, add:

```python
# Initialize mentor blueprint database
init_mentor_db(db)
print("Mentor blueprint tables initialized")
```

## 3. Database Migration

Since we've added new models, you may need to create and run a migration:

```bash
# If using Flask-Migrate
flask db migrate -m "Add mentor system"
flask db upgrade
```

Or manually create the tables by running the app once (the init functions will create them).

## 4. Update Existing Coupon Model (Optional)

If you want to integrate with the existing coupon system, you may need to add a migration to add the `mentor_id` field to your existing `coupon` table:

```sql
ALTER TABLE coupon ADD COLUMN mentor_id INTEGER;
```

## 5. Test the Integration

1. **Start the application**
2. **Access mentor login**: Go to `/mentor/login`
3. **Create a mentor**: Go to `/admin` → Login → Mentors → Create Mentor
4. **Test mentor login**: Use the generated credentials
5. **Assign coupons**: Go to Admin → Assign Coupons to link coupons with mentors

## 6. File Structure

After integration, your file structure should include:

```
CNT/
├── mentor.py                           # New mentor blueprint
├── templates/
│   ├── mentor/
│   │   ├── mentor_login.html          # New mentor login template
│   │   └── mentor_dashboard.html      # New mentor dashboard template
│   ├── admin/
│   │   ├── mentors.html               # New admin mentor management
│   │   ├── create_mentor.html         # New admin create mentor
│   │   └── assign_coupon.html         # New admin assign coupon
│   └── settings.html                  # Updated with mentor login button
├── test_mentor.py                     # New unit tests
└── MENTOR_INTEGRATION.md              # This file
```

## 7. Features Included

### For Mentors:
- **Login System**: Secure login with mentor_id and password
- **Dashboard**: View students who used their assigned coupons
- **Search & Pagination**: Find specific students easily
- **Statistics**: View coupon usage statistics

### For Admins:
- **Mentor Management**: Create, activate/deactivate mentors
- **Password Reset**: Generate new passwords for mentors
- **Coupon Assignment**: Link coupons to specific mentors
- **Dashboard Integration**: View mentor count and quick actions

### Security Features:
- **Password Hashing**: All passwords stored securely using werkzeug
- **Session Management**: Secure session-based authentication
- **Active Status Check**: Only active mentors can login
- **Admin Controls**: Full admin control over mentor accounts

## 8. Usage Flow

1. **Admin creates mentor** → System generates mentor_id and password
2. **Admin assigns coupons to mentor** → Links existing coupons to mentor
3. **Students use coupons** → System tracks which mentor's coupon was used
4. **Mentor logs in** → Views dashboard with their students
5. **Mentor searches/filters** → Finds specific students easily

## 9. Testing

Run the unit tests:

```bash
python test_mentor.py
```

## 10. Customization

You can customize:
- **Mentor ID format**: Modify `generate_mentor_id()` in mentor.py
- **Password complexity**: Modify `generate_mentor_password()` in mentor.py
- **Dashboard layout**: Edit `mentor_dashboard.html`
- **Pagination size**: Change `per_page=10` in dashboard route
- **Search fields**: Modify search query in dashboard route

## 11. Troubleshooting

**Common Issues:**

1. **Import Error**: Make sure mentor.py is in the same directory as app.py
2. **Database Error**: Run the init functions to create tables
3. **Template Not Found**: Ensure mentor templates are in templates/mentor/
4. **Route Not Found**: Check blueprint registration in app.py
5. **Session Issues**: Clear browser cookies if login doesn't work

**Debug Mode:**
Enable Flask debug mode to see detailed error messages:

```python
app.run(debug=True)
```