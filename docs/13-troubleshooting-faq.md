# Troubleshooting & FAQ

## 13.1 Common Issues

### 13.1.1 Authentication Problems

Common authentication-related issues and their solutions.

#### JWT Token Validation Failures

**Problem**: Users receiving 401 Unauthorized errors despite having valid credentials.

**Symptoms**:
- Login successful but subsequent API calls fail
- Error message: "Invalid token" or "Token expired"
- Intermittent authentication failures

**Debugging Steps**:

```bash
# Check JWT token structure
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | base64 -d

# Verify token expiration
node -e "
const jwt = require('jsonwebtoken');
const token = 'your-jwt-token-here';
try {
  const decoded = jwt.decode(token);
  console.log('Token payload:', decoded);
  console.log('Expires at:', new Date(decoded.exp * 1000));
  console.log('Current time:', new Date());
} catch (error) {
  console.error('Token decode error:', error.message);
}
"

# Check server logs for JWT validation errors
docker logs api-gateway-container | grep -i "jwt\|token\|auth"
```

**Common Causes & Solutions**:

1. **Clock Skew Issues**
   ```typescript
   // Solution: Add clock tolerance in JWT validation
   const decoded = jwt.verify(token, secretKey, {
     clockTolerance: 30, // 30 seconds tolerance
   });
   ```

2. **Incorrect Secret Key**
   ```bash
   # Verify environment variables
   echo $JWT_SECRET_KEY
   
   # Check if secret matches between services
   kubectl get secret jwt-secret -o yaml
   ```

3. **Token Blacklisting Issues**
   ```typescript
   // Check Redis for blacklisted tokens
   const isBlacklisted = await redis.get(`blacklist:${tokenId}`);
   console.log('Token blacklisted:', isBlacklisted);
   ```

#### AWS Cognito Integration Issues

**Problem**: Cognito authentication failures or user creation errors.

**Debugging Steps**:

```bash
# Test Cognito connectivity
aws cognito-idp list-users --user-pool-id us-east-1_XXXXXXXXX

# Check Cognito user pool configuration
aws cognito-idp describe-user-pool --user-pool-id us-east-1_XXXXXXXXX

# Verify app client settings
aws cognito-idp describe-user-pool-client \
  --user-pool-id us-east-1_XXXXXXXXX \
  --client-id your-client-id
```

**Common Solutions**:

1. **Invalid User Pool Configuration**
   ```typescript
   // Verify configuration matches Cognito settings
   const cognitoConfig = {
     userPoolId: process.env.COGNITO_USER_POOL_ID,
     clientId: process.env.COGNITO_CLIENT_ID,
     region: process.env.AWS_REGION || 'us-east-1',
   };
   ```

2. **Missing IAM Permissions**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "cognito-idp:AdminCreateUser",
           "cognito-idp:AdminSetUserPassword",
           "cognito-idp:AdminUpdateUserAttributes",
           "cognito-idp:AdminGetUser"
         ],
         "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
       }
     ]
   }
   ```

### 13.1.2 Authorization Failures

Role-based access control and permission issues.

#### Permission Denied Errors

**Problem**: Users with appropriate roles receiving 403 Forbidden errors.

**Debugging Steps**:

```typescript
// Debug permission checking
async function debugUserPermissions(tenantId: string, userId: string) {
  console.log('=== Permission Debug ===');
  
  // 1. Check user exists and is active
  const user = await userService.getUser(tenantId, userId);
  console.log('User:', {
    id: user?.userId,
    email: user?.email,
    status: user?.status,
    roles: user?.roles,
  });
  
  // 2. Check role permissions
  for (const roleName of user?.roles || []) {
    const role = await roleService.getRole(tenantId, roleName);
    console.log(`Role ${roleName}:`, {
      permissions: role?.permissions,
      isSystem: role?.isSystem,
    });
  }
  
  // 3. Check effective permissions
  const permissions = await permissionService.getUserPermissions(tenantId, userId);
  console.log('Effective permissions:', permissions);
  
  // 4. Test specific permission
  const hasPermission = await permissionService.checkPermission(
    permissions,
    'read:users:tenant'
  );
  console.log('Has read:users:tenant permission:', hasPermission);
}
```

**Common Causes & Solutions**:

1. **Role Assignment Issues**
   ```typescript
   // Verify user has correct roles
   const user = await userService.getUser(tenantId, userId);
   if (!user.roles.includes('admin')) {
     await userService.assignRole(tenantId, userId, 'admin');
   }
   ```

2. **Permission Format Errors**
   ```typescript
   // Correct permission format: action:resource:scope
   const validPermissions = [
     'read:users:tenant',
     'write:users:tenant',
     'delete:users:tenant',
     '*:*:*', // Super admin
   ];
   
   // Invalid formats
   const invalidPermissions = [
     'read-users', // Missing colons
     'read:users', // Missing scope
     'READ:USERS:TENANT', // Case sensitive
   ];
   ```

3. **Tenant Isolation Issues**
   ```typescript
   // Ensure tenant context is properly set
   const middleware = async (request, reply) => {
     const { tenantId } = request.user;
     if (!tenantId) {
       throw new Error('Missing tenant context');
     }
     
     // Verify user belongs to tenant
     const user = await userService.getUser(tenantId, request.user.userId);
     if (!user) {
       throw new ForbiddenError('User not found in tenant');
     }
   };
   ```

### 13.1.3 Performance Issues

Database and API performance troubleshooting.

#### Slow Database Queries

**Problem**: API responses are slow due to inefficient database queries.

**Debugging Steps**:

```bash
# Enable MongoDB profiling
mongo --eval "db.setProfilingLevel(2, { slowms: 100 })"

# Check slow queries
mongo --eval "db.system.profile.find().sort({ts: -1}).limit(5).pretty()"

# Analyze query execution
mongo --eval "
db.users.find({tenantId: 'tenant_123'}).explain('executionStats')
"
```

**Performance Optimization**:

```typescript
// 1. Add proper indexes
await db.collection('users').createIndex(
  { tenantId: 1, email: 1 },
  { unique: true }
);

// 2. Use aggregation for complex queries
const usersWithRoles = await db.collection('users').aggregate([
  { $match: { tenantId } },
  {
    $lookup: {
      from: 'roles',
      localField: 'roles',
      foreignField: 'name',
      as: 'roleDetails',
    },
  },
  {
    $project: {
      email: 1,
      profile: 1,
      roles: '$roleDetails.permissions',
    },
  },
]).toArray();

// 3. Implement pagination
const users = await db.collection('users')
  .find({ tenantId })
  .skip((page - 1) * limit)
  .limit(limit)
  .toArray();
```

#### Memory Leaks

**Problem**: Application memory usage continuously increases.

**Debugging Steps**:

```bash
# Monitor memory usage
docker stats api-gateway-container

# Generate heap dump
kill -USR2 $(pgrep node)

# Analyze heap dump with clinic.js
npm install -g clinic
clinic doctor -- node app.js
```

**Common Causes & Solutions**:

```typescript
// 1. Unclosed database connections
class DatabaseService {
  private connections = new Map();
  
  async getConnection(tenantId: string) {
    if (!this.connections.has(tenantId)) {
      const connection = await MongoClient.connect(connectionString);
      this.connections.set(tenantId, connection);
      
      // Set up cleanup on process exit
      process.on('SIGTERM', () => {
        connection.close();
      });
    }
    
    return this.connections.get(tenantId);
  }
}

// 2. Event listener leaks
class EventService {
  private listeners = new Set();
  
  addListener(event: string, handler: Function) {
    this.listeners.add(handler);
    eventEmitter.on(event, handler);
  }
  
  cleanup() {
    for (const handler of this.listeners) {
      eventEmitter.removeListener('event', handler);
    }
    this.listeners.clear();
  }
}

// 3. Cache without TTL
class CacheService {
  private cache = new Map();
  
  set(key: string, value: any, ttl: number = 3600) {
    this.cache.set(key, {
      value,
      expires: Date.now() + (ttl * 1000),
    });
    
    // Cleanup expired entries
    setTimeout(() => {
      this.cache.delete(key);
    }, ttl * 1000);
  }
}
```

## 13.2 Debugging Guide

### 13.2.1 Logging Analysis

Comprehensive logging strategies for effective debugging.

#### Structured Logging Setup

```typescript
// Winston logger configuration
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'api-gateway',
    version: process.env.APP_VERSION,
  },
  transports: [
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Request logging middleware
const requestLogger = (request: FastifyRequest, reply: FastifyReply, done: Function) => {
  const startTime = Date.now();
  
  reply.addHook('onSend', (request, reply, payload, done) => {
    const duration = Date.now() - startTime;
    
    logger.info('HTTP Request', {
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      duration,
      userAgent: request.headers['user-agent'],
      ip: request.ip,
      tenantId: request.user?.tenantId,
      userId: request.user?.userId,
    });
    
    done();
  });
  
  done();
};
```

#### Log Analysis Queries

```bash
# Find authentication failures
grep "authentication failed" logs/combined.log | jq '.timestamp, .ip, .userAgent'

# Analyze slow requests
grep '"duration"' logs/combined.log | jq 'select(.duration > 1000)' | head -10

# Check error patterns
grep '"level":"error"' logs/combined.log | jq '.message' | sort | uniq -c | sort -nr

# Monitor specific tenant activity
grep '"tenantId":"tenant_123"' logs/combined.log | jq '.timestamp, .method, .url, .statusCode'

# Find rate limiting events
grep "rate limit exceeded" logs/combined.log | jq '.ip' | sort | uniq -c | sort -nr
```

### 13.2.2 Error Tracing

Distributed tracing and error correlation techniques.

#### Request Tracing Implementation

```typescript
// Request ID middleware for tracing
import { v4 as uuidv4 } from 'uuid';

const requestTracing = (request: FastifyRequest, reply: FastifyReply, done: Function) => {
  // Generate or extract request ID
  const requestId = request.headers['x-request-id'] || uuidv4();
  
  // Add to request context
  request.requestId = requestId;
  
  // Add to response headers
  reply.header('x-request-id', requestId);
  
  // Create child logger with request context
  request.log = logger.child({
    requestId,
    tenantId: request.user?.tenantId,
    userId: request.user?.userId,
  });
  
  done();
};

// Error tracking with context
class ErrorTracker {
  static async trackError(
    error: Error,
    context: {
      requestId: string;
      tenantId?: string;
      userId?: string;
      operation: string;
    }
  ) {
    const errorId = uuidv4();
    
    const errorData = {
      errorId,
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      ...context,
    };
    
    // Log error
    logger.error('Application Error', errorData);
    
    // Store in database for analysis
    await db.collection('errors').insertOne(errorData);
    
    // Send to external monitoring (optional)
    if (process.env.SENTRY_DSN) {
      Sentry.captureException(error, {
        tags: {
          requestId: context.requestId,
          tenantId: context.tenantId,
          operation: context.operation,
        },
      });
    }
    
    return errorId;
  }
}

// Usage in route handlers
const createUserHandler = async (request: FastifyRequest, reply: FastifyReply) => {
  try {
    const user = await userService.createUser(
      request.user.tenantId,
      request.body
    );
    
    request.log.info('User created successfully', {
      userId: user.userId,
      email: user.email,
    });
    
    return { success: true, data: user };
  } catch (error) {
    const errorId = await ErrorTracker.trackError(error, {
      requestId: request.requestId,
      tenantId: request.user.tenantId,
      userId: request.user.userId,
      operation: 'createUser',
    });
    
    request.log.error('User creation failed', {
      errorId,
      error: error.message,
    });
    
    throw new InternalServerError('User creation failed', { errorId });
  }
};
```

### 13.2.3 Performance Profiling

Application performance monitoring and optimization.

#### Performance Monitoring Setup

```typescript
// Performance monitoring middleware
const performanceMonitoring = (request: FastifyRequest, reply: FastifyReply, done: Function) => {
  const startTime = process.hrtime.bigint();
  const startMemory = process.memoryUsage();
  
  reply.addHook('onSend', (request, reply, payload, done) => {
    const endTime = process.hrtime.bigint();
    const endMemory = process.memoryUsage();
    
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;
    
    // Log performance metrics
    request.log.info('Performance Metrics', {
      duration,
      memoryDelta,
      heapUsed: endMemory.heapUsed,
      external: endMemory.external,
    });
    
    // Alert on slow requests
    if (duration > 5000) { // 5 seconds
      request.log.warn('Slow Request Detected', {
        duration,
        url: request.url,
        method: request.method,
      });
    }
    
    done();
  });
  
  done();
};

// Database query profiling
class DatabaseProfiler {
  static async profileQuery<T>(
    operation: string,
    query: () => Promise<T>
  ): Promise<T> {
    const startTime = process.hrtime.bigint();
    
    try {
      const result = await query();
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;
      
      logger.info('Database Query', {
        operation,
        duration,
        success: true,
      });
      
      return result;
    } catch (error) {
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;
      
      logger.error('Database Query Failed', {
        operation,
        duration,
        error: error.message,
      });
      
      throw error;
    }
  }
}

// Usage example
const getUsers = async (tenantId: string) => {
  return DatabaseProfiler.profileQuery(
    'getUsers',
    () => db.collection('users').find({ tenantId }).toArray()
  );
};
```

## 13.3 Frequently Asked Questions

### 13.3.1 Implementation Questions

Common questions about implementing the Multi-Tenant API Gateway.

#### Q: How do I add a new tenant to the system?

**A**: Use the admin API to create a new tenant:

```bash
# Create tenant via API
curl -X POST http://localhost:3000/admin/tenants \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Company",
    "domain": "newcompany.com",
    "adminEmail": "admin@newcompany.com",
    "plan": "basic"
  }'
```

**Programmatic approach**:

```typescript
const newTenant = await tenantService.createTenant({
  name: 'New Company',
  domain: 'newcompany.com',
  adminEmail: 'admin@newcompany.com',
  settings: {
    maxUsers: 100,
    features: ['basic-auth', 'user-management'],
    billing: {
      plan: 'basic',
      maxApiCalls: 10000,
      billingEmail: 'billing@newcompany.com',
    },
  },
});

console.log('Tenant created:', newTenant.tenantId);
```

#### Q: How do I create custom roles with specific permissions?

**A**: Use the role management API:

```typescript
// Create custom role
const customRole = await roleService.createRole('tenant_123', {
  name: 'data-analyst',
  description: 'Can read and analyze data',
  permissions: [
    'read:users:tenant',
    'read:analytics:tenant',
    'execute:reports:tenant',
  ],
  isSystem: false,
});

// Assign role to user
await userService.assignRole('tenant_123', 'user_456', 'data-analyst');

// Check user permissions
const permissions = await permissionService.getUserPermissions('tenant_123', 'user_456');
console.log('User permissions:', permissions);
```

#### Q: How do I implement rate limiting for specific tenants?

**A**: Configure tenant-specific rate limits:

```typescript
// Tenant-specific rate limiting
const rateLimitConfig = {
  'tenant_123': { max: 1000, window: '1h' }, // Premium tenant
  'tenant_456': { max: 100, window: '1h' },  // Basic tenant
  default: { max: 50, window: '1h' },        // Default limit
};

const rateLimitMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const tenantId = request.user?.tenantId;
  const config = rateLimitConfig[tenantId] || rateLimitConfig.default;
  
  const key = `rate_limit:${tenantId}:${request.ip}`;
  const current = await redis.incr(key);
  
  if (current === 1) {
    await redis.expire(key, parseWindow(config.window));
  }
  
  if (current > config.max) {
    throw new TooManyRequestsError('Rate limit exceeded');
  }
  
  reply.header('X-RateLimit-Limit', config.max);
  reply.header('X-RateLimit-Remaining', Math.max(0, config.max - current));
};
```

### 13.3.2 Configuration Questions

Questions about system configuration and setup.

#### Q: How do I configure AWS Cognito integration?

**A**: Set up Cognito configuration:

```typescript
// Environment variables
const cognitoConfig = {
  userPoolId: process.env.COGNITO_USER_POOL_ID,
  clientId: process.env.COGNITO_CLIENT_ID,
  clientSecret: process.env.COGNITO_CLIENT_SECRET,
  region: process.env.AWS_REGION || 'us-east-1',
};

// Cognito service initialization
const cognitoService = new CognitoService(cognitoConfig);

// Custom attributes for multi-tenancy
const userAttributes = [
  {
    Name: 'custom:tenantId',
    Value: tenantId,
  },
  {
    Name: 'custom:roles',
    Value: JSON.stringify(userRoles),
  },
];
```

**AWS CLI setup**:

```bash
# Create user pool
aws cognito-idp create-user-pool \
  --pool-name "API Gateway Users" \
  --schema '[
    {
      "Name": "tenantId",
      "AttributeDataType": "String",
      "Mutable": true,
      "Required": false
    },
    {
      "Name": "roles",
      "AttributeDataType": "String",
      "Mutable": true,
      "Required": false
    }
  ]'

# Create app client
aws cognito-idp create-user-pool-client \
  --user-pool-id us-east-1_XXXXXXXXX \
  --client-name "API Gateway Client" \
  --generate-secret
```

#### Q: How do I set up MongoDB for multi-tenant data isolation?

**A**: Configure MongoDB with proper indexing and connection pooling:

```typescript
// MongoDB connection with multi-tenant support
const mongoConfig = {
  uri: process.env.MONGODB_URI,
  options: {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    bufferMaxEntries: 0,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
};

// Create tenant-aware indexes
const createIndexes = async (db: Db) => {
  // Users collection
  await db.collection('users').createIndexes([
    { key: { tenantId: 1, email: 1 }, unique: true },
    { key: { tenantId: 1, userId: 1 }, unique: true },
    { key: { cognitoUserId: 1 }, unique: true },
  ]);
  
  // Roles collection
  await db.collection('roles').createIndexes([
    { key: { tenantId: 1, name: 1 }, unique: true },
  ]);
  
  // Audit logs with TTL
  await db.collection('auditLogs').createIndexes([
    { key: { tenantId: 1, timestamp: -1 } },
    { key: { timestamp: 1 }, expireAfterSeconds: 31536000 }, // 1 year
  ]);
};
```

#### Q: How do I configure environment-specific settings?

**A**: Use environment-based configuration:

```typescript
// config/index.ts
interface Config {
  server: {
    port: number;
    host: string;
  };
  database: {
    uri: string;
    name: string;
  };
  auth: {
    jwtSecret: string;
    tokenExpiry: string;
  };
  aws: {
    region: string;
    cognito: {
      userPoolId: string;
      clientId: string;
    };
  };
}

const config: Config = {
  server: {
    port: parseInt(process.env.PORT || '3000'),
    host: process.env.HOST || '0.0.0.0',
  },
  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017',
    name: process.env.DB_NAME || 'api_gateway',
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    tokenExpiry: process.env.TOKEN_EXPIRY || '15m',
  },
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    cognito: {
      userPoolId: process.env.COGNITO_USER_POOL_ID!,
      clientId: process.env.COGNITO_CLIENT_ID!,
    },
  },
};

export default config;
```

**Environment files**:

```bash
# .env.development
NODE_ENV=development
PORT=3000
LOG_LEVEL=debug
MONGODB_URI=mongodb://localhost:27017
JWT_SECRET=dev-secret-key

# .env.production
NODE_ENV=production
PORT=8080
LOG_LEVEL=info
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net
JWT_SECRET=production-secret-key
```

### 13.3.3 Deployment Questions

Questions about deploying and scaling the system.

#### Q: How do I deploy the API Gateway to AWS ECS?

**A**: Use the provided deployment scripts:

```bash
# Build and push Docker image
docker build -t api-gateway:latest .
docker tag api-gateway:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/api-gateway:latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/api-gateway:latest

# Deploy using AWS CLI
aws ecs update-service \
  --cluster api-gateway-cluster \
  --service api-gateway-service \
  --force-new-deployment
```

**ECS Task Definition**:

```json
{
  "family": "api-gateway",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::123456789012:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "api-gateway",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/api-gateway:latest",
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
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:mongodb-uri"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/api-gateway",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Q: How do I scale the system for high traffic?

**A**: Implement horizontal scaling strategies:

```typescript
// Load balancer configuration
const loadBalancerConfig = {
  algorithm: 'round-robin',
  healthCheck: {
    path: '/health',
    interval: 30000,
    timeout: 5000,
    retries: 3,
  },
  instances: [
    { host: 'api-1.internal', port: 3000 },
    { host: 'api-2.internal', port: 3000 },
    { host: 'api-3.internal', port: 3000 },
  ],
};

// Database connection pooling
const mongoOptions = {
  maxPoolSize: 20, // Increase pool size
  minPoolSize: 5,
  maxIdleTimeMS: 30000,
  serverSelectionTimeoutMS: 5000,
};

// Redis clustering for caching
const redisCluster = new Redis.Cluster([
  { host: 'redis-1.cache.amazonaws.com', port: 6379 },
  { host: 'redis-2.cache.amazonaws.com', port: 6379 },
  { host: 'redis-3.cache.amazonaws.com', port: 6379 },
]);

// Auto-scaling configuration
const autoScalingConfig = {
  minCapacity: 2,
  maxCapacity: 10,
  targetCPUUtilization: 70,
  scaleUpCooldown: 300,
  scaleDownCooldown: 300,
};
```

#### Q: How do I monitor the system in production?

**A**: Set up comprehensive monitoring:

```typescript
// Health check endpoint
app.get('/health', async (request, reply) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION,
    uptime: process.uptime(),
    checks: {
      database: 'unknown',
      redis: 'unknown',
      cognito: 'unknown',
    },
  };
  
  try {
    // Database health check
    await db.admin().ping();
    health.checks.database = 'healthy';
  } catch (error) {
    health.checks.database = 'unhealthy';
    health.status = 'unhealthy';
  }
  
  try {
    // Redis health check
    await redis.ping();
    health.checks.redis = 'healthy';
  } catch (error) {
    health.checks.redis = 'unhealthy';
    health.status = 'unhealthy';
  }
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  return reply.code(statusCode).send(health);
});

// Metrics collection
const metrics = {
  requests: new Map(),
  errors: new Map(),
  responseTime: [],
};

const metricsMiddleware = (request, reply, done) => {
  const start = Date.now();
  
  reply.addHook('onSend', (request, reply, payload, done) => {
    const duration = Date.now() - start;
    const endpoint = `${request.method} ${request.routerPath}`;
    
    // Track request count
    metrics.requests.set(endpoint, (metrics.requests.get(endpoint) || 0) + 1);
    
    // Track errors
    if (reply.statusCode >= 400) {
      metrics.errors.set(endpoint, (metrics.errors.get(endpoint) || 0) + 1);
    }
    
    // Track response time
    metrics.responseTime.push(duration);
    
    done();
  });
  
  done();
};
```

This comprehensive troubleshooting and FAQ documentation provides practical solutions for common issues and answers to frequently asked questions about implementing, configuring, and deploying the Multi-Tenant API Gateway. 