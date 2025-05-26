# Deployment & Operations

## 10.1 Infrastructure Setup

### 10.1.1 AWS Services Configuration

Complete AWS infrastructure setup for the Multi-Tenant API Gateway.

#### Required AWS Services

```yaml
# infrastructure/aws-services.yml
services:
  cognito:
    user_pool: api-gateway-users
    app_client: api-gateway-client
    domain: auth.yourdomain.com
  
  ecs:
    cluster: api-gateway-cluster
    service: api-gateway-service
    task_definition: api-gateway-task
  
  load_balancer:
    type: application
    name: api-gateway-alb
    listeners:
      - port: 443
        protocol: HTTPS
        ssl_certificate: arn:aws:acm:region:account:certificate/cert-id
  
  cloudwatch:
    log_groups:
      - /aws/ecs/api-gateway
      - /aws/lambda/cognito-triggers
    
  secrets_manager:
    secrets:
      - api-gateway/mongodb-uri
      - api-gateway/jwt-secret
      - api-gateway/cognito-client-secret
```

#### Terraform Infrastructure

```hcl
# infrastructure/main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "api-gateway-vpc"
    Environment = var.environment
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  map_public_ip_on_launch = true

  tags = {
    Name = "api-gateway-public-${count.index + 1}"
    Type = "public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "api-gateway-private-${count.index + 1}"
    Type = "private"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "api-gateway-igw"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "api-gateway-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Environment = var.environment
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "api-gateway-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = var.environment == "production"

  tags = {
    Environment = var.environment
  }
}

# Security Groups
resource "aws_security_group" "alb" {
  name_prefix = "api-gateway-alb-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "api-gateway-alb-sg"
  }
}

resource "aws_security_group" "ecs_tasks" {
  name_prefix = "api-gateway-ecs-tasks-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "api-gateway-ecs-tasks-sg"
  }
}

# Cognito User Pool
resource "aws_cognito_user_pool" "main" {
  name = "api-gateway-users"

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = false
    require_uppercase = true
  }

  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    default_email_subject = "Your verification code"
    default_email_message = "Your verification code is {####}"
  }

  schema {
    attribute_data_type = "String"
    name               = "tenantId"
    required           = false
    mutable            = true
  }

  schema {
    attribute_data_type = "String"
    name               = "roles"
    required           = false
    mutable            = true
  }

  tags = {
    Environment = var.environment
  }
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "main" {
  name         = "api-gateway-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = true

  explicit_auth_flows = [
    "ADMIN_NO_SRP_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  access_token_validity  = 24
  id_token_validity      = 24
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

# Secrets Manager
resource "aws_secretsmanager_secret" "mongodb_uri" {
  name = "api-gateway/mongodb-uri"
  description = "MongoDB connection string"
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name = "api-gateway/jwt-secret"
  description = "JWT signing secret"
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/aws/ecs/api-gateway"
  retention_in_days = 30

  tags = {
    Environment = var.environment
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
}

# Data Sources
data "aws_availability_zones" "available" {
  state = "available"
}

# Outputs
output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "load_balancer_dns" {
  value = aws_lb.main.dns_name
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.main.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.main.id
}
```

### 10.1.2 MongoDB Atlas Setup

MongoDB Atlas configuration for production deployment.

#### Atlas Cluster Configuration

```javascript
// scripts/setup-mongodb-atlas.js
const { MongoClient } = require('mongodb');

class MongoDBAtlasSetup {
  constructor(connectionString) {
    this.client = new MongoClient(connectionString);
  }

  async setupDatabase() {
    try {
      await this.client.connect();
      const db = this.client.db('api-gateway');

      // Create collections with validation
      await this.createCollections(db);
      
      // Create indexes for performance
      await this.createIndexes(db);
      
      // Set up initial data
      await this.seedInitialData(db);

      console.log('MongoDB Atlas setup completed successfully');
    } catch (error) {
      console.error('MongoDB setup failed:', error);
      throw error;
    } finally {
      await this.client.close();
    }
  }

  async createCollections(db) {
    // Tenants collection
    await db.createCollection('tenants', {
      validator: {
        $jsonSchema: {
          bsonType: 'object',
          required: ['tenantId', 'name', 'status'],
          properties: {
            tenantId: { bsonType: 'string' },
            name: { bsonType: 'string' },
            status: { enum: ['active', 'suspended', 'inactive'] },
            settings: {
              bsonType: 'object',
              properties: {
                maxUsers: { bsonType: 'number' },
                features: { bsonType: 'array' },
                billing: {
                  bsonType: 'object',
                  properties: {
                    plan: { enum: ['free', 'basic', 'premium', 'enterprise'] }
                  }
                }
              }
            }
          }
        }
      }
    });

    // Users collection
    await db.createCollection('users', {
      validator: {
        $jsonSchema: {
          bsonType: 'object',
          required: ['tenantId', 'email', 'cognitoUserId'],
          properties: {
            tenantId: { bsonType: 'string' },
            email: { bsonType: 'string' },
            cognitoUserId: { bsonType: 'string' },
            roles: { bsonType: 'array' },
            status: { enum: ['active', 'inactive', 'pending'] }
          }
        }
      }
    });

    // Roles collection
    await db.createCollection('roles', {
      validator: {
        $jsonSchema: {
          bsonType: 'object',
          required: ['tenantId', 'name', 'permissions'],
          properties: {
            tenantId: { bsonType: 'string' },
            name: { bsonType: 'string' },
            permissions: { bsonType: 'array' },
            isSystem: { bsonType: 'bool' }
          }
        }
      }
    });

    // Audit logs collection
    await db.createCollection('auditLogs', {
      validator: {
        $jsonSchema: {
          bsonType: 'object',
          required: ['tenantId', 'action', 'timestamp'],
          properties: {
            tenantId: { bsonType: 'string' },
            action: { bsonType: 'string' },
            timestamp: { bsonType: 'date' }
          }
        }
      }
    });
  }

  async createIndexes(db) {
    // Tenants indexes
    await db.collection('tenants').createIndexes([
      { key: { tenantId: 1 }, unique: true },
      { key: { domain: 1 }, unique: true, sparse: true },
      { key: { status: 1 } },
      { key: { createdAt: 1 } }
    ]);

    // Users indexes
    await db.collection('users').createIndexes([
      { key: { tenantId: 1, email: 1 }, unique: true },
      { key: { cognitoUserId: 1 }, unique: true },
      { key: { tenantId: 1, status: 1 } },
      { key: { tenantId: 1, roles: 1 } },
      { key: { lastLoginAt: 1 } }
    ]);

    // Roles indexes
    await db.collection('roles').createIndexes([
      { key: { tenantId: 1, name: 1 }, unique: true },
      { key: { tenantId: 1, isSystem: 1 } },
      { key: { permissions: 1 } }
    ]);

    // Audit logs indexes
    await db.collection('auditLogs').createIndexes([
      { key: { tenantId: 1, timestamp: -1 } },
      { key: { userId: 1, timestamp: -1 } },
      { key: { action: 1, timestamp: -1 } },
      { key: { timestamp: 1 }, expireAfterSeconds: 7776000 } // 90 days retention
    ]);

    // API keys indexes
    await db.collection('apiKeys').createIndexes([
      { key: { tenantId: 1, keyId: 1 }, unique: true },
      { key: { hashedKey: 1 }, unique: true },
      { key: { tenantId: 1, status: 1 } },
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 }
    ]);
  }

  async seedInitialData(db) {
    // Create system tenant for admin operations
    const systemTenant = {
      tenantId: 'system',
      name: 'System Administration',
      settings: {
        maxUsers: -1,
        features: ['*'],
        billing: {
          plan: 'enterprise',
          maxApiCalls: -1
        }
      },
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await db.collection('tenants').insertOne(systemTenant);

    // Create system roles
    const systemRoles = [
      {
        tenantId: 'system',
        name: 'superadmin',
        description: 'Full system access',
        permissions: ['*:*:*'],
        isSystem: true,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        tenantId: 'system',
        name: 'support',
        description: 'Support team access',
        permissions: [
          'read:tenants:global',
          'read:users:global',
          'read:audit-logs:global'
        ],
        isSystem: true,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ];

    await db.collection('roles').insertMany(systemRoles);
  }
}

module.exports = MongoDBAtlasSetup;
```

#### Atlas Configuration Script

```bash
#!/bin/bash
# scripts/setup-atlas.sh

# Set variables
ATLAS_PROJECT_ID="your-project-id"
ATLAS_CLUSTER_NAME="api-gateway-cluster"
ATLAS_USERNAME="admin"
ATLAS_PASSWORD="secure-password"

# Create Atlas cluster
atlas clusters create $ATLAS_CLUSTER_NAME \
  --provider AWS \
  --region US_EAST_1 \
  --tier M10 \
  --diskSizeGB 10 \
  --backup \
  --projectId $ATLAS_PROJECT_ID

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
atlas clusters watch $ATLAS_CLUSTER_NAME --projectId $ATLAS_PROJECT_ID

# Create database user
atlas dbusers create \
  --username $ATLAS_USERNAME \
  --password $ATLAS_PASSWORD \
  --role readWriteAnyDatabase \
  --projectId $ATLAS_PROJECT_ID

# Configure IP whitelist
atlas accessLists create \
  --cidr 0.0.0.0/0 \
  --comment "Allow all IPs for development" \
  --projectId $ATLAS_PROJECT_ID

# Get connection string
CONNECTION_STRING=$(atlas clusters connectionStrings describe $ATLAS_CLUSTER_NAME --projectId $ATLAS_PROJECT_ID)
echo "Connection string: $CONNECTION_STRING"

# Store in AWS Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id api-gateway/mongodb-uri \
  --secret-string "$CONNECTION_STRING"

echo "MongoDB Atlas setup completed!"
```

### 10.1.3 Environment Configuration

Environment-specific configuration management.

```yaml
# config/environments/production.yml
environment: production

server:
  port: 3000
  host: 0.0.0.0
  cors:
    origin: 
      - https://admin.yourdomain.com
      - https://api.yourdomain.com
    credentials: true

database:
  mongodb:
    uri: ${MONGODB_URI}
    options:
      maxPoolSize: 10
      serverSelectionTimeoutMS: 5000
      socketTimeoutMS: 45000

auth:
  cognito:
    region: ${AWS_REGION}
    userPoolId: ${COGNITO_USER_POOL_ID}
    clientId: ${COGNITO_CLIENT_ID}
    clientSecret: ${COGNITO_CLIENT_SECRET}
  jwt:
    secret: ${JWT_SECRET}
    expiresIn: 24h

cache:
  redis:
    enabled: true
    host: ${REDIS_HOST}
    port: ${REDIS_PORT}
    password: ${REDIS_PASSWORD}
    ttl: 300

logging:
  level: info
  format: json
  destinations:
    - console
    - cloudwatch

monitoring:
  metrics:
    enabled: true
    interval: 60
  healthCheck:
    enabled: true
    path: /health
    interval: 30

security:
  rateLimit:
    windowMs: 900000  # 15 minutes
    max: 100
  cors:
    enabled: true
  helmet:
    enabled: true
```

## 10.2 Deployment Strategies

### 10.2.1 Docker Containerization

Complete Docker setup for the API Gateway.

```dockerfile
# Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Create app user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/healthcheck.js

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Start application
CMD ["node", "dist/server.js"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  api-gateway:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=${MONGODB_URI}
      - AWS_COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
      - AWS_COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "dist/healthcheck.js"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - api-gateway
    restart: unless-stopped

volumes:
  redis_data:
```

### 10.2.2 CI/CD Pipeline

GitHub Actions workflow for automated deployment.

```yaml
# .github/workflows/deploy.yml
name: Deploy API Gateway

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: api-gateway
  ECS_SERVICE: api-gateway-service
  ECS_CLUSTER: api-gateway-cluster
  ECS_TASK_DEFINITION: api-gateway-task

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      mongodb:
        image: mongo:6.0
        ports:
          - 27017:27017
      redis:
        image: redis:7
        ports:
          - 6379:6379

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run linting
      run: npm run lint

    - name: Run type checking
      run: npm run type-check

    - name: Run tests
      run: npm test
      env:
        NODE_ENV: test
        MONGODB_URI: mongodb://localhost:27017/test
        REDIS_URL: redis://localhost:6379

    - name: Run integration tests
      run: npm run test:integration
      env:
        NODE_ENV: test
        MONGODB_URI: mongodb://localhost:27017/test
        REDIS_URL: redis://localhost:6379

  build-and-deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}

    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v1

    - name: Build, tag, and push image to Amazon ECR
      id: build-image
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
        docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
        echo "image=$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG" >> $GITHUB_OUTPUT

    - name: Fill in the new image ID in the Amazon ECS task definition
      id: task-def
      uses: aws-actions/amazon-ecs-render-task-definition@v1
      with:
        task-definition: task-definition.json
        container-name: api-gateway
        image: ${{ steps.build-image.outputs.image }}

    - name: Deploy Amazon ECS task definition
      uses: aws-actions/amazon-ecs-deploy-task-definition@v1
      with:
        task-definition: ${{ steps.task-def.outputs.task-definition }}
        service: ${{ env.ECS_SERVICE }}
        cluster: ${{ env.ECS_CLUSTER }}
        wait-for-service-stability: true

    - name: Run database migrations
      run: |
        aws ecs run-task \
          --cluster ${{ env.ECS_CLUSTER }} \
          --task-definition ${{ env.ECS_TASK_DEFINITION }} \
          --overrides '{"containerOverrides":[{"name":"api-gateway","command":["npm","run","migrate"]}]}'

  notify:
    needs: [test, build-and-deploy]
    runs-on: ubuntu-latest
    if: always()
    
    steps:
    - name: Notify Slack
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### 10.2.3 Blue-Green Deployment

Blue-green deployment strategy for zero-downtime deployments.

```yaml
# scripts/blue-green-deploy.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: blue-green-deploy-script
data:
  deploy.sh: |
    #!/bin/bash
    set -e
    
    # Configuration
    CLUSTER_NAME="api-gateway-cluster"
    SERVICE_NAME="api-gateway-service"
    NEW_IMAGE="$1"
    
    if [ -z "$NEW_IMAGE" ]; then
      echo "Usage: $0 <new-image>"
      exit 1
    fi
    
    echo "Starting blue-green deployment..."
    echo "New image: $NEW_IMAGE"
    
    # Get current task definition
    CURRENT_TASK_DEF=$(aws ecs describe-services \
      --cluster $CLUSTER_NAME \
      --services $SERVICE_NAME \
      --query 'services[0].taskDefinition' \
      --output text)
    
    echo "Current task definition: $CURRENT_TASK_DEF"
    
    # Create new task definition with new image
    NEW_TASK_DEF=$(aws ecs describe-task-definition \
      --task-definition $CURRENT_TASK_DEF \
      --query 'taskDefinition' \
      --output json | \
      jq --arg IMAGE "$NEW_IMAGE" \
      '.containerDefinitions[0].image = $IMAGE | 
       del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .placementConstraints, .compatibilities, .registeredAt, .registeredBy)' | \
      aws ecs register-task-definition \
      --cli-input-json file:///dev/stdin \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text)
    
    echo "New task definition: $NEW_TASK_DEF"
    
    # Update service with new task definition
    echo "Updating service..."
    aws ecs update-service \
      --cluster $CLUSTER_NAME \
      --service $SERVICE_NAME \
      --task-definition $NEW_TASK_DEF
    
    # Wait for deployment to complete
    echo "Waiting for deployment to complete..."
    aws ecs wait services-stable \
      --cluster $CLUSTER_NAME \
      --services $SERVICE_NAME
    
    # Health check
    echo "Performing health check..."
    LOAD_BALANCER_DNS=$(aws elbv2 describe-load-balancers \
      --names api-gateway-alb \
      --query 'LoadBalancers[0].DNSName' \
      --output text)
    
    for i in {1..10}; do
      if curl -f "http://$LOAD_BALANCER_DNS/health"; then
        echo "Health check passed!"
        break
      else
        echo "Health check failed, attempt $i/10"
        sleep 30
      fi
    done
    
    # Verify deployment
    RUNNING_TASKS=$(aws ecs list-tasks \
      --cluster $CLUSTER_NAME \
      --service-name $SERVICE_NAME \
      --desired-status RUNNING \
      --query 'taskArns' \
      --output text | wc -w)
    
    echo "Deployment completed successfully!"
    echo "Running tasks: $RUNNING_TASKS"
    
    # Clean up old task definitions (keep last 5)
    echo "Cleaning up old task definitions..."
    aws ecs list-task-definitions \
      --family-prefix api-gateway \
      --status ACTIVE \
      --sort DESC \
      --query 'taskDefinitionArns[5:]' \
      --output text | \
      xargs -n1 aws ecs deregister-task-definition --task-definition
    
    echo "Blue-green deployment completed!"
```

## 10.3 Monitoring and Maintenance

### 10.3.1 Health Check Implementation

Comprehensive health checking system.

```typescript
// src/health/healthCheck.ts
import { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import Redis from 'ioredis';

interface HealthStatus {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  uptime: number;
  version: string;
  checks: {
    database: HealthCheckResult;
    cache: HealthCheckResult;
    cognito: HealthCheckResult;
    memory: HealthCheckResult;
    disk: HealthCheckResult;
  };
}

interface HealthCheckResult {
  status: 'pass' | 'fail' | 'warn';
  responseTime: number;
  message?: string;
  details?: any;
}

export class HealthCheckService {
  private mongoClient: MongoClient;
  private redisClient: Redis;
  private startTime: number;

  constructor(mongoClient: MongoClient, redisClient: Redis) {
    this.mongoClient = mongoClient;
    this.redisClient = redisClient;
    this.startTime = Date.now();
  }

  async getHealthStatus(): Promise<HealthStatus> {
    const checks = await Promise.allSettled([
      this.checkDatabase(),
      this.checkCache(),
      this.checkCognito(),
      this.checkMemory(),
      this.checkDisk()
    ]);

    const healthChecks = {
      database: this.getResultValue(checks[0]),
      cache: this.getResultValue(checks[1]),
      cognito: this.getResultValue(checks[2]),
      memory: this.getResultValue(checks[3]),
      disk: this.getResultValue(checks[4])
    };

    const overallStatus = this.determineOverallStatus(healthChecks);

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: Date.now() - this.startTime,
      version: process.env.npm_package_version || '1.0.0',
      checks: healthChecks
    };
  }

  private async checkDatabase(): Promise<HealthCheckResult> {
    const startTime = Date.now();
    
    try {
      await this.mongoClient.db('admin').command({ ping: 1 });
      
      return {
        status: 'pass',
        responseTime: Date.now() - startTime,
        message: 'Database connection successful'
      };
    } catch (error) {
      return {
        status: 'fail',
        responseTime: Date.now() - startTime,
        message: 'Database connection failed',
        details: error.message
      };
    }
  }

  private async checkCache(): Promise<HealthCheckResult> {
    const startTime = Date.now();
    
    try {
      await this.redisClient.ping();
      
      return {
        status: 'pass',
        responseTime: Date.now() - startTime,
        message: 'Cache connection successful'
      };
    } catch (error) {
      return {
        status: 'warn',
        responseTime: Date.now() - startTime,
        message: 'Cache connection failed - operating without cache',
        details: error.message
      };
    }
  }

  private async checkCognito(): Promise<HealthCheckResult> {
    const startTime = Date.now();
    
    try {
      const AWS = require('aws-sdk');
      const cognito = new AWS.CognitoIdentityServiceProvider();
      
      await cognito.describeUserPool({
        UserPoolId: process.env.COGNITO_USER_POOL_ID
      }).promise();
      
      return {
        status: 'pass',
        responseTime: Date.now() - startTime,
        message: 'Cognito connection successful'
      };
    } catch (error) {
      return {
        status: 'fail',
        responseTime: Date.now() - startTime,
        message: 'Cognito connection failed',
        details: error.message
      };
    }
  }

  private async checkMemory(): Promise<HealthCheckResult> {
    const memUsage = process.memoryUsage();
    const totalMem = memUsage.heapTotal;
    const usedMem = memUsage.heapUsed;
    const memoryUsagePercent = (usedMem / totalMem) * 100;

    let status: 'pass' | 'warn' | 'fail' = 'pass';
    let message = 'Memory usage normal';

    if (memoryUsagePercent > 90) {
      status = 'fail';
      message = 'Critical memory usage';
    } else if (memoryUsagePercent > 80) {
      status = 'warn';
      message = 'High memory usage';
    }

    return {
      status,
      responseTime: 0,
      message,
      details: {
        heapUsed: Math.round(usedMem / 1024 / 1024),
        heapTotal: Math.round(totalMem / 1024 / 1024),
        usagePercent: Math.round(memoryUsagePercent)
      }
    };
  }

  private async checkDisk(): Promise<HealthCheckResult> {
    try {
      const fs = require('fs');
      const stats = fs.statSync('/');
      
      return {
        status: 'pass',
        responseTime: 0,
        message: 'Disk access successful'
      };
    } catch (error) {
      return {
        status: 'fail',
        responseTime: 0,
        message: 'Disk access failed',
        details: error.message
      };
    }
  }

  private getResultValue(result: PromiseSettledResult<HealthCheckResult>): HealthCheckResult {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      return {
        status: 'fail',
        responseTime: 0,
        message: 'Health check failed',
        details: result.reason
      };
    }
  }

  private determineOverallStatus(checks: Record<string, HealthCheckResult>): 'healthy' | 'unhealthy' | 'degraded' {
    const statuses = Object.values(checks).map(check => check.status);
    
    if (statuses.includes('fail')) {
      // Critical services failed
      const criticalFailed = checks.database.status === 'fail' || checks.cognito.status === 'fail';
      return criticalFailed ? 'unhealthy' : 'degraded';
    }
    
    if (statuses.includes('warn')) {
      return 'degraded';
    }
    
    return 'healthy';
  }
}

// Health check endpoint
export function registerHealthRoutes(fastify: FastifyInstance, healthService: HealthCheckService) {
  // Liveness probe
  fastify.get('/health/live', async (request, reply) => {
    return { status: 'alive', timestamp: new Date().toISOString() };
  });

  // Readiness probe
  fastify.get('/health/ready', async (request, reply) => {
    const health = await healthService.getHealthStatus();
    
    if (health.status === 'unhealthy') {
      reply.code(503);
    } else if (health.status === 'degraded') {
      reply.code(200);
    }
    
    return health;
  });

  // Detailed health check
  fastify.get('/health', async (request, reply) => {
    const health = await healthService.getHealthStatus();
    
    if (health.status === 'unhealthy') {
      reply.code(503);
    }
    
    return health;
  });
}
```

### 10.3.2 Logging and Monitoring Setup

Comprehensive logging and monitoring configuration.

```typescript
// src/monitoring/logger.ts
import winston from 'winston';
import CloudWatchTransport from 'winston-cloudwatch';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: {
    service: 'api-gateway',
    version: process.env.npm_package_version,
    environment: process.env.NODE_ENV
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Add CloudWatch transport in production
if (process.env.NODE_ENV === 'production') {
  logger.add(new CloudWatchTransport({
    logGroupName: '/aws/ecs/api-gateway',
    logStreamName: `${process.env.HOSTNAME || 'unknown'}-${Date.now()}`,
    awsRegion: process.env.AWS_REGION || 'us-east-1',
    messageFormatter: ({ level, message, timestamp, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        message,
        ...meta
      });
    }
  }));
}

export default logger;
```

```typescript
// src/monitoring/metrics.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';

// HTTP request metrics
export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code', 'tenant_id'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
});

export const httpRequestTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code', 'tenant_id']
});

// Authentication metrics
export const authenticationAttempts = new Counter({
  name: 'authentication_attempts_total',
  help: 'Total number of authentication attempts',
  labelNames: ['result', 'tenant_id']
});

export const authenticationDuration = new Histogram({
  name: 'authentication_duration_seconds',
  help: 'Duration of authentication requests',
  labelNames: ['tenant_id'],
  buckets: [0.1, 0.5, 1, 2, 5]
});

// Database metrics
export const databaseOperationDuration = new Histogram({
  name: 'database_operation_duration_seconds',
  help: 'Duration of database operations',
  labelNames: ['operation', 'collection', 'tenant_id'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
});

export const databaseConnectionsActive = new Gauge({
  name: 'database_connections_active',
  help: 'Number of active database connections'
});

// Cache metrics
export const cacheOperations = new Counter({
  name: 'cache_operations_total',
  help: 'Total number of cache operations',
  labelNames: ['operation', 'result']
});

export const cacheHitRatio = new Gauge({
  name: 'cache_hit_ratio',
  help: 'Cache hit ratio'
});

// Business metrics
export const tenantsActive = new Gauge({
  name: 'tenants_active_total',
  help: 'Number of active tenants'
});

export const usersActive = new Gauge({
  name: 'users_active_total',
  help: 'Number of active users',
  labelNames: ['tenant_id']
});

export const apiCallsPerTenant = new Counter({
  name: 'api_calls_per_tenant_total',
  help: 'Total API calls per tenant',
  labelNames: ['tenant_id', 'endpoint']
});

// Error metrics
export const errorRate = new Counter({
  name: 'errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'tenant_id']
});

// Export metrics endpoint
export function getMetrics() {
  return register.metrics();
}
```

### 10.3.3 Backup and Recovery

Automated backup and recovery procedures.

```bash
#!/bin/bash
# scripts/backup-mongodb.sh

set -e

# Configuration
BACKUP_DIR="/backups"
RETENTION_DAYS=30
MONGODB_URI="${MONGODB_URI}"
S3_BUCKET="api-gateway-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="mongodb_backup_${DATE}"

echo "Starting MongoDB backup: ${BACKUP_NAME}"

# Create backup directory
mkdir -p ${BACKUP_DIR}/${BACKUP_NAME}

# Perform backup
mongodump --uri="${MONGODB_URI}" --out=${BACKUP_DIR}/${BACKUP_NAME}

# Compress backup
cd ${BACKUP_DIR}
tar -czf ${BACKUP_NAME}.tar.gz ${BACKUP_NAME}/
rm -rf ${BACKUP_NAME}/

# Upload to S3
aws s3 cp ${BACKUP_NAME}.tar.gz s3://${S3_BUCKET}/mongodb/${BACKUP_NAME}.tar.gz

# Verify upload
if aws s3 ls s3://${S3_BUCKET}/mongodb/${BACKUP_NAME}.tar.gz; then
    echo "Backup uploaded successfully to S3"
    rm ${BACKUP_NAME}.tar.gz
else
    echo "Failed to upload backup to S3"
    exit 1
fi

# Clean up old backups
find ${BACKUP_DIR} -name "mongodb_backup_*.tar.gz" -mtime +${RETENTION_DAYS} -delete

# Clean up old S3 backups
aws s3 ls s3://${S3_BUCKET}/mongodb/ | \
    awk '{print $4}' | \
    grep "mongodb_backup_" | \
    head -n -${RETENTION_DAYS} | \
    xargs -I {} aws s3 rm s3://${S3_BUCKET}/mongodb/{}

echo "MongoDB backup completed: ${BACKUP_NAME}"
```

```bash
#!/bin/bash
# scripts/restore-mongodb.sh

set -e

BACKUP_NAME="$1"
MONGODB_URI="${MONGODB_URI}"
S3_BUCKET="api-gateway-backups"
RESTORE_DIR="/tmp/restore"

if [ -z "$BACKUP_NAME" ]; then
    echo "Usage: $0 <backup_name>"
    echo "Available backups:"
    aws s3 ls s3://${S3_BUCKET}/mongodb/ | grep "mongodb_backup_"
    exit 1
fi

echo "Starting MongoDB restore from backup: ${BACKUP_NAME}"

# Create restore directory
mkdir -p ${RESTORE_DIR}
cd ${RESTORE_DIR}

# Download backup from S3
aws s3 cp s3://${S3_BUCKET}/mongodb/${BACKUP_NAME}.tar.gz .

# Extract backup
tar -xzf ${BACKUP_NAME}.tar.gz

# Confirm restore
read -p "This will overwrite the current database. Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled"
    exit 1
fi

# Perform restore
mongorestore --uri="${MONGODB_URI}" --drop ${BACKUP_NAME}/

# Clean up
rm -rf ${RESTORE_DIR}

echo "MongoDB restore completed from backup: ${BACKUP_NAME}"
```

## 10.4 Scaling Considerations

### 10.4.1 Horizontal Scaling

Auto-scaling configuration for the API Gateway.

```json
{
  "family": "api-gateway-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "api-gateway",
      "image": "account.dkr.ecr.region.amazonaws.com/api-gateway:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "MONGODB_URI",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:api-gateway/mongodb-uri"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:api-gateway/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/aws/ecs/api-gateway",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health/live || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

```hcl
# Auto Scaling Configuration
resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_policy_cpu" {
  name               = "api-gateway-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_appautoscaling_policy" "ecs_policy_memory" {
  name               = "api-gateway-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value = 80.0
  }
}
```

### 10.4.2 Database Scaling

MongoDB Atlas auto-scaling configuration.

```javascript
// scripts/setup-atlas-autoscaling.js
const { MongoClient } = require('mongodb');

class AtlasAutoScaling {
  constructor(atlasApiKey, atlasApiSecret, projectId) {
    this.atlasApiKey = atlasApiKey;
    this.atlasApiSecret = atlasApiSecret;
    this.projectId = projectId;
  }

  async enableAutoScaling(clusterName) {
    const config = {
      compute: {
        enabled: true,
        scaleDownEnabled: true,
        minInstanceSize: "M10",
        maxInstanceSize: "M40"
      },
      diskGB: {
        enabled: true
      }
    };

    // Enable auto-scaling via Atlas API
    const response = await this.makeAtlasRequest(
      'PATCH',
      `/groups/${this.projectId}/clusters/${clusterName}/processArgs`,
      config
    );

    console.log('Auto-scaling enabled:', response);
  }

  async configureReadReplicas(clusterName) {
    const config = {
      replicationSpecs: [
        {
          numShards: 1,
          regionsConfig: {
            "US_EAST_1": {
              electableNodes: 3,
              priority: 7,
              readOnlyNodes: 2
            },
            "US_WEST_2": {
              electableNodes: 0,
              priority: 0,
              readOnlyNodes: 2
            }
          }
        }
      ]
    };

    const response = await this.makeAtlasRequest(
      'PATCH',
      `/groups/${this.projectId}/clusters/${clusterName}`,
      config
    );

    console.log('Read replicas configured:', response);
  }

  async makeAtlasRequest(method, path, data) {
    const fetch = require('node-fetch');
    const auth = Buffer.from(`${this.atlasApiKey}:${this.atlasApiSecret}`).toString('base64');

    const response = await fetch(`https://cloud.mongodb.com/api/atlas/v1.0${path}`, {
      method,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json'
      },
      body: data ? JSON.stringify(data) : undefined
    });

    return response.json();
  }
}

module.exports = AtlasAutoScaling;
```

### 10.4.3 Performance Tuning

Performance optimization strategies and configurations.

```typescript
// src/performance/optimization.ts
import { FastifyInstance } from 'fastify';
import Redis from 'ioredis';

export class PerformanceOptimizer {
  private redis: Redis;
  private fastify: FastifyInstance;

  constructor(fastify: FastifyInstance, redis: Redis) {
    this.fastify = fastify;
    this.redis = redis;
  }

  async setupOptimizations() {
    // Connection pooling
    this.setupConnectionPooling();
    
    // Response compression
    this.setupCompression();
    
    // Caching strategies
    this.setupCaching();
    
    // Request optimization
    this.setupRequestOptimization();
  }

  private setupConnectionPooling() {
    // MongoDB connection pooling is configured in the connection string
    // Redis connection pooling
    const redisOptions = {
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
      enableReadyCheck: false,
      maxLoadingTimeout: 1000,
      lazyConnect: true,
      keepAlive: 30000,
      family: 4,
      connectTimeout: 10000,
      commandTimeout: 5000
    };

    console.log('Connection pooling configured');
  }

  private setupCompression() {
    this.fastify.register(require('@fastify/compress'), {
      global: true,
      threshold: 1024,
      encodings: ['gzip', 'deflate']
    });

    console.log('Response compression enabled');
  }

  private setupCaching() {
    // Cache frequently accessed data
    this.fastify.addHook('onRequest', async (request, reply) => {
      if (request.method === 'GET') {
        const cacheKey = this.generateCacheKey(request);
        const cached = await this.redis.get(cacheKey);
        
        if (cached) {
          reply.header('X-Cache', 'HIT');
          reply.send(JSON.parse(cached));
          return;
        }
        
        request.cacheKey = cacheKey;
      }
    });

    this.fastify.addHook('onSend', async (request, reply, payload) => {
      if (request.cacheKey && reply.statusCode === 200) {
        await this.redis.setex(request.cacheKey, 300, payload);
        reply.header('X-Cache', 'MISS');
      }
    });

    console.log('Caching strategies configured');
  }

  private setupRequestOptimization() {
    // Request size limits
    this.fastify.register(require('@fastify/formbody'), {
      bodyLimit: 1048576 // 1MB
    });

    // Request timeout
    this.fastify.server.timeout = 30000; // 30 seconds

    // Keep-alive
    this.fastify.server.keepAliveTimeout = 65000;
    this.fastify.server.headersTimeout = 66000;

    console.log('Request optimization configured');
  }

  private generateCacheKey(request: any): string {
    const { method, url, headers } = request;
    const tenantId = headers['x-tenant-id'] || 'default';
    return `cache:${method}:${tenantId}:${url}`;
  }
}

// Performance monitoring
export class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();

  recordMetric(name: string, value: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    const values = this.metrics.get(name)!;
    values.push(value);
    
    // Keep only last 1000 values
    if (values.length > 1000) {
      values.shift();
    }
  }

  getMetricStats(name: string) {
    const values = this.metrics.get(name) || [];
    
    if (values.length === 0) {
      return null;
    }

    const sorted = [...values].sort((a, b) => a - b);
    const sum = values.reduce((a, b) => a + b, 0);

    return {
      count: values.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: sum / values.length,
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }

  getAllMetrics() {
    const result: Record<string, any> = {};
    
    for (const [name] of this.metrics) {
      result[name] = this.getMetricStats(name);
    }
    
    return result;
  }
}
```

This completes the comprehensive Deployment & Operations documentation section, covering infrastructure setup, deployment strategies, monitoring, and scaling considerations for the Multi-Tenant API Gateway project. 