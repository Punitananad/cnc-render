# AWS Deployment Guide for CalculatenTrade

## Option 1: AWS Elastic Beanstalk (Recommended)

### Prerequisites
1. AWS Account
2. AWS CLI installed and configured
3. EB CLI installed

### Step 1: Install AWS CLI and EB CLI
```bash
# Install AWS CLI
pip install awscli

# Install EB CLI
pip install awsebcli

# Configure AWS credentials
aws configure
```

### Step 2: Initialize Elastic Beanstalk
```bash
cd CNT
eb init

# Select:
# - Region: Choose your preferred region
# - Application name: calculatentrade
# - Platform: Python 3.9
# - SSH: Yes (recommended)
```

### Step 3: Create Environment and Deploy
```bash
# Create environment
eb create production

# Deploy updates
eb deploy

# Open in browser
eb open
```

### Step 4: Set Environment Variables
```bash
eb setenv FLASK_ENV=production SECRET_KEY=your-secret-key
```

## Option 2: AWS EC2 Manual Setup

### Step 1: Launch EC2 Instance
1. Go to AWS Console → EC2
2. Launch Instance (Ubuntu 22.04 LTS)
3. Instance type: t3.micro (free tier) or t3.small
4. Configure security group: Allow HTTP (80), HTTPS (443), SSH (22)

### Step 2: Connect and Setup
```bash
# Connect to instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3-pip python3-venv nginx -y

# Install TA-Lib system dependencies
sudo apt install build-essential wget -y
wget http://prdownloads.sourceforge.net/ta-lib/ta-lib-0.4.0-src.tar.gz
tar -xzf ta-lib-0.4.0-src.tar.gz
cd ta-lib/
./configure --prefix=/usr
make
sudo make install
cd ..

# Clone your code (upload via SCP or Git)
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-aws.txt

# Setup Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 application:application
```

### Step 3: Configure Nginx (Optional)
```bash
sudo nano /etc/nginx/sites-available/calculatentrade

# Add configuration:
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /static {
        alias /path/to/your/app/static;
    }
}

# Enable site
sudo ln -s /etc/nginx/sites-available/calculatentrade /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

## Option 3: AWS App Runner (Serverless)

### Step 1: Create Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements-aws.txt .
RUN pip install -r requirements-aws.txt

COPY . .
EXPOSE 5000

CMD ["python", "application.py"]
```

### Step 2: Push to ECR or GitHub
1. Push code to GitHub repository
2. Go to AWS App Runner console
3. Create service from GitHub repository
4. Configure build settings

## Environment Variables Needed

Set these in your AWS environment:
- `FLASK_ENV=production`
- `SECRET_KEY=your-secret-key`
- `DATABASE_URL=your-database-url` (if using external DB)

## Database Considerations

For production, consider:
1. **AWS RDS** for PostgreSQL/MySQL
2. **Amazon DynamoDB** for NoSQL
3. Current SQLite works for small scale

## Cost Estimates

- **Elastic Beanstalk**: $10-50/month
- **EC2 t3.micro**: $8-15/month
- **App Runner**: $0.064/hour + requests
- **RDS db.t3.micro**: $15-25/month

## Security Checklist

- [ ] Set strong SECRET_KEY
- [ ] Use HTTPS (SSL certificate)
- [ ] Configure security groups properly
- [ ] Set up backup strategy
- [ ] Monitor application logs
- [ ] Use environment variables for secrets

## Monitoring

Set up CloudWatch for:
- Application logs
- Performance metrics
- Error tracking
- Uptime monitoring