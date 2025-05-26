# Getting Started

## 2.1 Prerequisites

### Required Tools and Accounts

#### Development Tools
- **Node.js**: Version 18.0 or higher
- **npm**: Version 8.0 or higher (comes with Node.js)
- **Git**: Latest version
- **Docker**: Version 20.0 or higher (for containerization)
- **Docker Compose**: Version 2.0 or higher

#### Cloud Services
- **AWS Account**: For Cognito and deployment
- **MongoDB Atlas Account**: For database hosting (or local MongoDB)

#### Development Environment
- **Code Editor**: VS Code (recommended) with extensions:
  - TypeScript and JavaScript Language Features
  - ESLint
  - Prettier
  - MongoDB for VS Code
  - AWS Toolkit

### Installation Commands

```bash
# Check Node.js version
node --version  # Should be 18.0+

# Check npm version
npm --version   # Should be 8.0+

# Install global dependencies
npm install -g typescript ts-node nodemon

# Check Docker installation
docker --version
docker-compose --version
```

## 2.2 Development Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/multi-tenant-api-gateway.git
cd multi-tenant-api-gateway
```

### 2. Install Dependencies

```bash
# Install backend dependencies
npm install

# Install frontend dependencies (if admin panel is included)
cd admin-panel
npm install
cd ..
```

### 3. Environment Configuration

Create environment files for different environments:

```bash
# Create environment files
cp .env.example .env.development
cp .env.example .env.production
```

#### .env.development Example

```bash
# Application Configuration
NODE_ENV=development
PORT=3000
API_VERSION=v1

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/api-gateway-dev
MONGODB_DB_NAME=api_gateway_dev

# AWS Cognito Configuration
AWS_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
AWS_COGNITO_CLIENT_ID=your-client-id
AWS_COGNITO_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# Security Configuration
CORS_ORIGIN=http://localhost:3001
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=15

# Logging Configuration
LOG_LEVEL=debug
LOG_FORMAT=dev

# Admin Panel Configuration
ADMIN_PANEL_URL=http://localhost:3001
SUPERADMIN_EMAIL=admin@example.com
```

### 4. Database Setup

#### Option A: Local MongoDB with Docker

```bash
# Start MongoDB container
docker-compose up -d mongodb

# Verify MongoDB is running
docker ps
```

#### Option B: MongoDB Atlas (Recommended for production)

1. Create a MongoDB Atlas account
2. Create a new cluster
3. Get connection string and update `MONGODB_URI` in `.env`

### 5. AWS Cognito Setup

#### Create Cognito User Pool

```bash
# Using AWS CLI (optional)
aws cognito-idp create-user-pool \
  --pool-name "api-gateway-users" \
  --policies PasswordPolicy='{MinimumLength=8,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true}' \
  --auto-verified-attributes email
```

#### Manual Setup (AWS Console)
1. Go to AWS Cognito Console
2. Create User Pool
3. Configure sign-in options (email)
4. Set password policy
5. Create app client
6. Note down User Pool ID and Client ID

## 2.3 Project Structure

```
multi-tenant-api-gateway/
├── src/                          # Source code
│   ├── controllers/              # Route controllers
│   ├── middleware/               # Custom middleware
│   ├── models/                   # Data models
│   ├── services/                 # Business logic
│   ├── utils/                    # Utility functions
│   ├── routes/                   # API routes
│   └── app.ts                    # Application entry point
├── admin-panel/                  # Frontend admin panel
│   ├── src/
│   ├── public/
│   └── package.json
├── tests/                        # Test files
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── docs/                         # Documentation
├── scripts/                      # Utility scripts
├── docker/                       # Docker configurations
├── .env.example                  # Environment template
├── docker-compose.yml            # Local development setup
├── package.json                  # Dependencies
└── README.md                     # Project readme
```

### Key Directories Explained

- **src/controllers/**: Handle HTTP requests and responses
- **src/middleware/**: Authentication, authorization, validation
- **src/models/**: MongoDB schemas and data models
- **src/services/**: Business logic and external service integrations
- **src/routes/**: API endpoint definitions
- **tests/**: Comprehensive test suite
- **admin-panel/**: React/Vue.js admin interface

## 2.4 Quick Start Guide

### 1. Start Development Environment

```bash
# Start all services with Docker Compose
docker-compose up -d

# Or start services individually
npm run dev:db      # Start MongoDB
npm run dev:api     # Start API Gateway
npm run dev:admin   # Start Admin Panel
```

### 2. Initialize Database

```bash
# Run database migrations and seed data
npm run db:migrate
npm run db:seed
```

### 3. Verify Installation

```bash
# Check API health
curl http://localhost:3000/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "services": {
    "database": "connected",
    "cognito": "configured"
  }
}
```

### 4. Access Admin Panel

Open browser and navigate to: `http://localhost:3001`

Default superadmin credentials:
- Email: `admin@example.com`
- Password: `TempPassword123!`

### 5. Test API Endpoints

```bash
# Get JWT token (replace with actual Cognito user)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Use token to access protected endpoint
curl -X GET http://localhost:3000/api/v1/tenants \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 2.5 Configuration Management

### Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `NODE_ENV` | Environment mode | Yes | development |
| `PORT` | Server port | No | 3000 |
| `MONGODB_URI` | MongoDB connection string | Yes | - |
| `AWS_COGNITO_USER_POOL_ID` | Cognito User Pool ID | Yes | - |
| `AWS_COGNITO_CLIENT_ID` | Cognito Client ID | Yes | - |
| `JWT_SECRET` | JWT signing secret | Yes | - |
| `CORS_ORIGIN` | Allowed CORS origins | No | * |
| `LOG_LEVEL` | Logging level | No | info |

### Configuration Validation

The application validates configuration on startup:

```javascript
// src/config/validation.ts
const configSchema = {
  NODE_ENV: { required: true, enum: ['development', 'production', 'test'] },
  PORT: { required: false, type: 'number', default: 3000 },
  MONGODB_URI: { required: true, type: 'string' },
  AWS_COGNITO_USER_POOL_ID: { required: true, type: 'string' },
  // ... other validations
};
```

### Development Scripts

```json
{
  "scripts": {
    "dev": "nodemon src/app.ts",
    "build": "tsc",
    "start": "node dist/app.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "db:migrate": "ts-node scripts/migrate.ts",
    "db:seed": "ts-node scripts/seed.ts",
    "docker:build": "docker build -t api-gateway .",
    "docker:run": "docker run -p 3000:3000 api-gateway"
  }
}
```

## Common Setup Issues

### Issue: MongoDB Connection Failed
```bash
# Check if MongoDB is running
docker ps | grep mongo

# Check connection string format
# Correct: mongodb://localhost:27017/dbname
# Incorrect: mongodb://localhost/dbname
```

### Issue: Cognito Configuration Error
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check Cognito User Pool exists
aws cognito-idp describe-user-pool --user-pool-id YOUR_POOL_ID
```

### Issue: Port Already in Use
```bash
# Find process using port 3000
lsof -i :3000

# Kill process
kill -9 PID
```

## Next Steps

1. **Configure AWS Cognito** (Section 3.1)
2. **Set up MongoDB Multi-Tenant Design** (Section 4.1)
3. **Implement Authentication Flow** (Section 3.3)
4. **Create First Tenant** (Section 4.2)

## Development Workflow

1. Create feature branch: `git checkout -b feature/auth-implementation`
2. Make changes and test locally
3. Run tests: `npm test`
4. Commit changes: `git commit -m "feat: implement JWT validation"`
5. Push and create pull request
6. Deploy to staging environment
7. Merge to main after review 