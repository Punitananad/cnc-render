# Frontend Testing Guide

## Quick Start Testing

### 1. Start the Flask Server
```bash
python app.py
```

### 2. Run Smoke Tests
```bash
# Python version (recommended)
python run_tests.py

# Bash version
chmod +x test_frontend.sh
./test_frontend.sh

# Node.js version (requires puppeteer)
npm install puppeteer
node test_frontend.js
```

## Manual Testing Checklist

### Core Pages to Test:
1. **Home Page** (`/`) - Should load with navigation and content
2. **Login Page** (`/login`) - Form should be functional
3. **Dashboard** (`/calculatentrade_journal/dashboard`) - Should show trading stats
4. **Trades Journal** (`/calculatentrade_journal/trades`) - Table and sidebar should work
5. **Admin Panel** (`/admin/login`) - Should load with Gentelella theme

### Key Elements to Verify:
- [ ] Sidebar toggle button works (click hamburger menu)
- [ ] Navigation links are clickable
- [ ] Forms submit properly
- [ ] Tables load and display data
- [ ] Mobile responsive design works
- [ ] No JavaScript console errors
- [ ] CSS styles load correctly

### Sidebar Functionality Test:
1. Go to `/calculatentrade_journal/trades`
2. Click the hamburger menu (☰) in top-left
3. Sidebar should slide in/out on mobile
4. Sidebar should collapse/expand on desktop
5. Navigation links in sidebar should work

## Troubleshooting

### If Tests Fail:
1. **Server not running**: Start with `python app.py`
2. **Port conflicts**: Check if port 5000 is available
3. **Template errors**: Check Flask console for error messages
4. **Static files 404**: Verify files exist in `/static/` directory

### Common Issues:
- **Sidebar not working**: Check browser console for JavaScript errors
- **Pages not loading**: Verify Flask routes are registered
- **Styling broken**: Check if CSS files are loading (Network tab in DevTools)

## Expected Test Results

### Successful Test Output:
```
🚀 Starting Frontend Smoke Tests...
✅ Server is running at http://localhost:5000
✅ Static file: /static/css/gentelella.css
✅ Static file: /static/js/gentelella.js
✅ Home Page: OK (HTTP 200)
✅ Login Page: OK (HTTP 200)
✅ Admin Login: OK (HTTP 200)
🎉 All tests passed!
```

### What Each Test Verifies:
- **Server Running**: Flask application is accessible
- **Static Files**: CSS/JS files load without 404 errors
- **Page Loading**: Templates render without errors
- **Content Present**: Expected text/elements are on pages
- **Status Codes**: Proper HTTP responses (200 for pages, 302 for redirects)

## Browser Testing

### Recommended Browsers:
- Chrome/Chromium (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

### Mobile Testing:
- Use browser DevTools mobile simulation
- Test on actual mobile devices if available
- Verify sidebar works on touch devices