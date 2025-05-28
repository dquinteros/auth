
# Multi-Tenant API Gateway

This repository contains a Node.js based API Gateway designed for multi-tenant applications. The gateway handles authentication, authorization and request routing across multiple backend services. It integrates with AWS Cognito for user management and uses MongoDB for data storage.

## Quick Start

1. **Install dependencies**

```bash
npm install
```

2. **Create your environment configuration**

Copy `.env.example` to `.env` and update the values as needed. The template lists
required AWS settings along with optional values such as `PORT` and `MONGODB_URI`.

```bash
cp .env.example .env
```

3. **Configure AWS Cognito**

Run the setup script to create the user pool and app client. You can override the
region, pool name and client name with environment variables:

```bash
AWS_REGION=us-east-1 \
COGNITO_USER_POOL_NAME=my-pool \
COGNITO_APP_CLIENT_NAME=my-client \
./aws/setup-cognito.sh
```

## Development

```bash
npm run dev
```
