# 14. Appendices

## 14.1 Configuration Reference

### 14.1.1 Environment Variables

#### Core Application Settings
```bash
# Server Configuration
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

# Database Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/api-gateway
MONGODB_DB_NAME=api_gateway
MONGODB_MAX_POOL_SIZE=10
MONGODB_MIN_POOL_SIZE=2

# AWS Cognito Configuration
AWS_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
AWS_COGNITO_CLIENT_ID=your-client-id
AWS_COGNITO_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Redis Configuration (for caching)
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
REDIS_TTL=3600

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS=false

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE_PATH=/var/log/api-gateway.log

# Security Configuration
CORS_ORIGIN=https://yourdomain.com
CORS_CREDENTIALS=true
HELMET_ENABLED=true
BCRYPT_ROUNDS=12

# Performance Configuration
REQUEST_TIMEOUT=30000
KEEP_ALIVE_TIMEOUT=5000
BODY_LIMIT=1mb

# Monitoring Configuration
HEALTH_CHECK_INTERVAL=30000
METRICS_ENABLED=true
PROMETHEUS_PORT=9090

# Admin Panel Configuration
ADMIN_PANEL_URL=https://admin.yourdomain.com
ADMIN_SESSION_SECRET=your-admin-session-secret
ADMIN_SESSION_TIMEOUT=3600000
```

#### Development Environment
```bash
# Development specific overrides
NODE_ENV=development
LOG_LEVEL=debug
LOG_FORMAT=pretty
CORS_ORIGIN=http://localhost:3000,http://localhost:8080
MONGODB_URI=mongodb://localhost:27017/api_gateway_dev
REDIS_URL=redis://localhost:6379
```

#### Testing Environment
```bash
# Testing specific overrides
NODE_ENV=test
LOG_LEVEL=silent
MONGODB_URI=mongodb://localhost:27017/api_gateway_test
REDIS_URL=redis://localhost:6379/1
JWT_EXPIRES_IN=1h
RATE_LIMIT_MAX_REQUESTS=1000
```

### 14.1.2 Configuration Files

#### Fastify Server Configuration
```typescript
// config/server.ts
export const serverConfig = {
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    prettyPrint: process.env.NODE_ENV === 'development'
  },
  trustProxy: true,
  bodyLimit: parseInt(process.env.BODY_LIMIT || '1048576'),
  keepAliveTimeout: parseInt(process.env.KEEP_ALIVE_TIMEOUT || '5000'),
  connectionTimeout: parseInt(process.env.REQUEST_TIMEOUT || '30000'),
  pluginTimeout: 10000,
  requestIdHeader: 'x-request-id',
  requestIdLogLabel: 'reqId'
};
```

#### Database Configuration
```typescript
// config/database.ts
export const databaseConfig = {
  uri: process.env.MONGODB_URI!,
  options: {
    maxPoolSize: parseInt(process.env.MONGODB_MAX_POOL_SIZE || '10'),
    minPoolSize: parseInt(process.env.MONGODB_MIN_POOL_SIZE || '2'),
    maxIdleTimeMS: 30000,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    bufferMaxEntries: 0,
    useNewUrlParser: true,
    useUnifiedTopology: true
  }
};
```

#### Security Configuration
```typescript
// config/security.ts
export const securityConfig = {
  cors: {
    origin: process.env.CORS_ORIGIN?.split(',') || false,
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID']
  },
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
    skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS === 'true'
  }
};
```

### 14.1.3 Default Settings

#### Default Roles and Permissions
```typescript
// config/defaults.ts
export const defaultRoles = [
  {
    name: 'super_admin',
    description: 'Full system access',
    permissions: ['*'],
    isSystemRole: true
  },
  {
    name: 'tenant_admin',
    description: 'Full tenant access',
    permissions: [
      'tenant:read',
      'tenant:update',
      'users:*',
      'roles:*',
      'api:*'
    ],
    isSystemRole: true
  },
  {
    name: 'user',
    description: 'Basic user access',
    permissions: [
      'profile:read',
      'profile:update',
      'api:read'
    ],
    isSystemRole: true
  }
];

export const defaultPermissions = [
  // Tenant permissions
  { name: 'tenant:create', description: 'Create new tenants' },
  { name: 'tenant:read', description: 'View tenant information' },
  { name: 'tenant:update', description: 'Update tenant settings' },
  { name: 'tenant:delete', description: 'Delete tenants' },
  
  // User permissions
  { name: 'users:create', description: 'Create new users' },
  { name: 'users:read', description: 'View user information' },
  { name: 'users:update', description: 'Update user details' },
  { name: 'users:delete', description: 'Delete users' },
  
  // Role permissions
  { name: 'roles:create', description: 'Create new roles' },
  { name: 'roles:read', description: 'View role information' },
  { name: 'roles:update', description: 'Update role permissions' },
  { name: 'roles:delete', description: 'Delete roles' },
  
  // API permissions
  { name: 'api:read', description: 'Read API access' },
  { name: 'api:write', description: 'Write API access' },
  { name: 'api:admin', description: 'Administrative API access' }
];
```

## 14.2 API Reference

### 14.2.1 Complete Endpoint List

#### Authentication Endpoints
```
POST   /auth/login              - User login
POST   /auth/refresh            - Refresh JWT token
POST   /auth/logout             - User logout
GET    /auth/me                 - Get current user info
POST   /auth/forgot-password    - Request password reset
POST   /auth/reset-password     - Reset password
```

#### Tenant Management Endpoints
```
GET    /api/tenants             - List all tenants (super admin)
POST   /api/tenants             - Create new tenant (super admin)
GET    /api/tenants/:id         - Get tenant details
PUT    /api/tenants/:id         - Update tenant
DELETE /api/tenants/:id         - Delete tenant (super admin)
GET    /api/tenants/:id/users   - List tenant users
POST   /api/tenants/:id/users   - Add user to tenant
```

#### User Management Endpoints
```
GET    /api/users               - List users (tenant scope)
POST   /api/users               - Create new user
GET    /api/users/:id           - Get user details
PUT    /api/users/:id           - Update user
DELETE /api/users/:id           - Delete user
PUT    /api/users/:id/roles     - Assign roles to user
GET    /api/users/:id/permissions - Get user permissions
```

#### Role Management Endpoints
```
GET    /api/roles               - List roles (tenant scope)
POST   /api/roles               - Create new role
GET    /api/roles/:id           - Get role details
PUT    /api/roles/:id           - Update role
DELETE /api/roles/:id           - Delete role
PUT    /api/roles/:id/permissions - Assign permissions to role
```

#### API Gateway Endpoints
```
GET    /api/routes              - List configured routes
POST   /api/routes              - Create new route
PUT    /api/routes/:id          - Update route
DELETE /api/routes/:id          - Delete route
GET    /api/routes/:id/metrics  - Get route metrics
```

#### System Endpoints
```
GET    /health                  - Health check
GET    /metrics                 - Prometheus metrics
GET    /api/audit               - Audit logs (admin only)
GET    /api/system/info         - System information
```

### 14.2.2 Request/Response Examples

#### User Login
```bash
# Request
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'

# Response
{
  "success": true,
  "data": {
    "user": {
      "id": "507f1f77bcf86cd799439011",
      "email": "user@example.com",
      "tenantId": "507f1f77bcf86cd799439012",
      "roles": ["user"]
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 86400
    }
  }
}
```

#### Create Tenant
```bash
# Request
curl -X POST http://localhost:3000/api/tenants \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "name": "Acme Corporation",
    "domain": "acme.com",
    "settings": {
      "maxUsers": 100,
      "features": ["api_access", "advanced_analytics"]
    }
  }'

# Response
{
  "success": true,
  "data": {
    "id": "507f1f77bcf86cd799439013",
    "name": "Acme Corporation",
    "domain": "acme.com",
    "status": "active",
    "settings": {
      "maxUsers": 100,
      "features": ["api_access", "advanced_analytics"]
    },
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  }
}
```

#### API Gateway Route Configuration
```bash
# Request
curl -X POST http://localhost:3000/api/routes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Tenant-ID: 507f1f77bcf86cd799439012" \
  -d '{
    "path": "/api/v1/products",
    "method": "GET",
    "target": "http://products-service:3001/products",
    "authentication": true,
    "permissions": ["api:read"],
    "rateLimit": {
      "requests": 100,
      "window": "1h"
    }
  }'

# Response
{
  "success": true,
  "data": {
    "id": "507f1f77bcf86cd799439014",
    "path": "/api/v1/products",
    "method": "GET",
    "target": "http://products-service:3001/products",
    "tenantId": "507f1f77bcf86cd799439012",
    "authentication": true,
    "permissions": ["api:read"],
    "rateLimit": {
      "requests": 100,
      "window": "1h"
    },
    "status": "active",
    "createdAt": "2024-01-15T10:35:00Z"
  }
}
```

### 14.2.3 Error Code Reference

#### HTTP Status Codes
```typescript
// Standard HTTP status codes used
200 - OK                    // Successful request
201 - Created              // Resource created successfully
204 - No Content           // Successful request with no response body
400 - Bad Request          // Invalid request data
401 - Unauthorized         // Authentication required
403 - Forbidden            // Insufficient permissions
404 - Not Found            // Resource not found
409 - Conflict             // Resource conflict (duplicate)
422 - Unprocessable Entity // Validation errors
429 - Too Many Requests    // Rate limit exceeded
500 - Internal Server Error // Server error
503 - Service Unavailable  // Service temporarily unavailable
```

#### Custom Error Codes
```typescript
// Authentication Errors (AUTH_*)
AUTH_001 - Invalid credentials
AUTH_002 - Token expired
AUTH_003 - Token invalid
AUTH_004 - Token missing
AUTH_005 - Refresh token invalid
AUTH_006 - Account locked
AUTH_007 - Password reset required

// Authorization Errors (AUTHZ_*)
AUTHZ_001 - Insufficient permissions
AUTHZ_002 - Tenant access denied
AUTHZ_003 - Resource access denied
AUTHZ_004 - Role not found
AUTHZ_005 - Permission not found

// Validation Errors (VAL_*)
VAL_001 - Required field missing
VAL_002 - Invalid field format
VAL_003 - Field value out of range
VAL_004 - Invalid email format
VAL_005 - Password too weak
VAL_006 - Invalid tenant domain

// Resource Errors (RES_*)
RES_001 - Tenant not found
RES_002 - User not found
RES_003 - Role not found
RES_004 - Route not found
RES_005 - Duplicate resource
RES_006 - Resource limit exceeded

// System Errors (SYS_*)
SYS_001 - Database connection error
SYS_002 - External service unavailable
SYS_003 - Configuration error
SYS_004 - Rate limit exceeded
SYS_005 - Service overloaded
```

#### Error Response Format
```typescript
{
  "success": false,
  "error": {
    "code": "AUTH_001",
    "message": "Invalid credentials provided",
    "details": "The email or password is incorrect",
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req_123456789",
    "path": "/auth/login"
  }
}
```

## 14.3 Database Schema

### 14.3.1 Collection Definitions

#### Tenants Collection
```typescript
// Collection: tenants
interface Tenant {
  _id: ObjectId;
  name: string;                    // Tenant display name
  domain: string;                  // Unique domain identifier
  status: 'active' | 'suspended' | 'inactive';
  settings: {
    maxUsers: number;
    maxApiCalls: number;
    features: string[];            // Enabled features
    customization: {
      logo?: string;
      theme?: object;
      branding?: object;
    };
  };
  subscription: {
    plan: string;
    startDate: Date;
    endDate?: Date;
    status: 'active' | 'expired' | 'cancelled';
  };
  contact: {
    email: string;
    phone?: string;
    address?: {
      street: string;
      city: string;
      state: string;
      country: string;
      zipCode: string;
    };
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy: ObjectId;             // User who created the tenant
}
```

#### Users Collection
```typescript
// Collection: users
interface User {
  _id: ObjectId;
  tenantId: ObjectId;              // Reference to tenant
  email: string;                   // Unique within tenant
  cognitoUserId: string;           // AWS Cognito user ID
  profile: {
    firstName: string;
    lastName: string;
    avatar?: string;
    phone?: string;
    timezone?: string;
    language?: string;
  };
  roles: ObjectId[];               // Array of role references
  status: 'active' | 'inactive' | 'suspended';
  lastLoginAt?: Date;
  loginCount: number;
  preferences: {
    notifications: boolean;
    theme: 'light' | 'dark';
    language: string;
  };
  metadata: Record<string, any>;   // Custom tenant-specific data
  createdAt: Date;
  updatedAt: Date;
  createdBy: ObjectId;
}
```

#### Roles Collection
```typescript
// Collection: roles
interface Role {
  _id: ObjectId;
  tenantId: ObjectId;              // Reference to tenant (null for system roles)
  name: string;                    // Unique within tenant
  description: string;
  permissions: string[];           // Array of permission strings
  isSystemRole: boolean;           // Cannot be modified by tenants
  isDefault: boolean;              // Assigned to new users by default
  hierarchy: number;               // Role hierarchy level (0 = highest)
  metadata: {
    color?: string;
    icon?: string;
    category?: string;
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy: ObjectId;
}
```

#### Routes Collection
```typescript
// Collection: routes
interface Route {
  _id: ObjectId;
  tenantId: ObjectId;              // Reference to tenant
  path: string;                    // API path pattern
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | '*';
  target: string;                  // Backend service URL
  authentication: boolean;         // Requires authentication
  permissions: string[];           // Required permissions
  rateLimit?: {
    requests: number;
    window: string;                // Time window (e.g., '1h', '1m')
    skipSuccessfulRequests?: boolean;
  };
  transformation?: {
    request?: object;              // Request transformation rules
    response?: object;             // Response transformation rules
  };
  caching?: {
    enabled: boolean;
    ttl: number;                   // Cache TTL in seconds
    key?: string;                  // Custom cache key pattern
  };
  status: 'active' | 'inactive';
  metadata: {
    description?: string;
    tags?: string[];
    version?: string;
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy: ObjectId;
}
```

#### Audit Logs Collection
```typescript
// Collection: audit_logs
interface AuditLog {
  _id: ObjectId;
  tenantId: ObjectId;              // Reference to tenant
  userId?: ObjectId;               // User who performed the action
  action: string;                  // Action performed
  resource: string;                // Resource affected
  resourceId?: ObjectId;           // ID of affected resource
  details: {
    method: string;                // HTTP method
    path: string;                  // Request path
    userAgent?: string;
    ipAddress?: string;
    changes?: object;              // What changed (for updates)
  };
  result: 'success' | 'failure';
  errorCode?: string;              // Error code if failed
  timestamp: Date;
  requestId: string;               // Correlation ID
}
```

### 14.3.2 Index Specifications

#### Tenants Collection Indexes
```javascript
// Unique domain index
db.tenants.createIndex({ "domain": 1 }, { unique: true });

// Status and creation date for admin queries
db.tenants.createIndex({ "status": 1, "createdAt": -1 });

// Subscription status for billing queries
db.tenants.createIndex({ "subscription.status": 1, "subscription.endDate": 1 });
```

#### Users Collection Indexes
```javascript
// Compound index for tenant-scoped email uniqueness
db.users.createIndex({ "tenantId": 1, "email": 1 }, { unique: true });

// Cognito user ID for authentication
db.users.createIndex({ "cognitoUserId": 1 }, { unique: true });

// Status and last login for user management
db.users.createIndex({ "tenantId": 1, "status": 1, "lastLoginAt": -1 });

// Role-based queries
db.users.createIndex({ "tenantId": 1, "roles": 1 });
```

#### Roles Collection Indexes
```javascript
// Compound index for tenant-scoped role uniqueness
db.roles.createIndex({ "tenantId": 1, "name": 1 }, { unique: true });

// System roles query
db.roles.createIndex({ "isSystemRole": 1 });

// Default roles for user creation
db.roles.createIndex({ "tenantId": 1, "isDefault": 1 });

// Hierarchy for role management
db.roles.createIndex({ "tenantId": 1, "hierarchy": 1 });
```

#### Routes Collection Indexes
```javascript
// Compound index for route matching
db.routes.createIndex({ "tenantId": 1, "path": 1, "method": 1 }, { unique: true });

// Status for active route queries
db.routes.createIndex({ "tenantId": 1, "status": 1 });

// Permission-based route queries
db.routes.createIndex({ "tenantId": 1, "permissions": 1 });
```

#### Audit Logs Collection Indexes
```javascript
// Tenant and timestamp for log queries
db.audit_logs.createIndex({ "tenantId": 1, "timestamp": -1 });

// User activity tracking
db.audit_logs.createIndex({ "userId": 1, "timestamp": -1 });

// Action and resource for specific log queries
db.audit_logs.createIndex({ "tenantId": 1, "action": 1, "resource": 1, "timestamp": -1 });

// Request ID for correlation
db.audit_logs.createIndex({ "requestId": 1 });

// TTL index for log retention (optional)
db.audit_logs.createIndex({ "timestamp": 1 }, { expireAfterSeconds: 7776000 }); // 90 days
```

### 14.3.3 Relationship Diagrams

#### Entity Relationship Diagram (Mermaid)
```mermaid
erDiagram
    TENANT ||--o{ USER : contains
    TENANT ||--o{ ROLE : defines
    TENANT ||--o{ ROUTE : configures
    TENANT ||--o{ AUDIT_LOG : generates
    
    USER ||--o{ AUDIT_LOG : performs
    USER }o--o{ ROLE : assigned
    
    ROLE ||--o{ PERMISSION : contains
    
    TENANT {
        ObjectId _id PK
        string name
        string domain UK
        string status
        object settings
        object subscription
        object contact
        Date createdAt
        Date updatedAt
        ObjectId createdBy FK
    }
    
    USER {
        ObjectId _id PK
        ObjectId tenantId FK
        string email
        string cognitoUserId UK
        object profile
        ObjectId[] roles FK
        string status
        Date lastLoginAt
        number loginCount
        object preferences
        object metadata
        Date createdAt
        Date updatedAt
        ObjectId createdBy FK
    }
    
    ROLE {
        ObjectId _id PK
        ObjectId tenantId FK
        string name
        string description
        string[] permissions
        boolean isSystemRole
        boolean isDefault
        number hierarchy
        object metadata
        Date createdAt
        Date updatedAt
        ObjectId createdBy FK
    }
    
    ROUTE {
        ObjectId _id PK
        ObjectId tenantId FK
        string path
        string method
        string target
        boolean authentication
        string[] permissions
        object rateLimit
        object transformation
        object caching
        string status
        object metadata
        Date createdAt
        Date updatedAt
        ObjectId createdBy FK
    }
    
    AUDIT_LOG {
        ObjectId _id PK
        ObjectId tenantId FK
        ObjectId userId FK
        string action
        string resource
        ObjectId resourceId
        object details
        string result
        string errorCode
        Date timestamp
        string requestId
    }
```

#### Data Flow Diagram
```mermaid
flowchart TD
    A[Client Request] --> B[API Gateway]
    B --> C{Authentication Required?}
    C -->|Yes| D[JWT Validation]
    C -->|No| E[Route Matching]
    D --> F{Valid Token?}
    F -->|No| G[401 Unauthorized]
    F -->|Yes| H[Extract User & Tenant]
    H --> I[Permission Check]
    I --> J{Has Permission?}
    J -->|No| K[403 Forbidden]
    J -->|Yes| E
    E --> L{Route Found?}
    L -->|No| M[404 Not Found]
    L -->|Yes| N[Rate Limiting]
    N --> O{Rate Limit OK?}
    O -->|No| P[429 Too Many Requests]
    O -->|Yes| Q[Forward to Backend]
    Q --> R[Backend Service]
    R --> S[Response Processing]
    S --> T[Audit Logging]
    T --> U[Return Response]
    
    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style R fill:#e8f5e8
    style U fill:#fff3e0
```

## 14.4 Security Considerations

### 14.4.1 Threat Model

#### Assets
- **User Data**: Personal information, credentials, preferences
- **Tenant Data**: Business information, configurations, API keys
- **System Data**: Authentication tokens, audit logs, system configurations
- **API Access**: Backend services, data endpoints, administrative functions

#### Threat Actors
- **External Attackers**: Unauthorized access attempts, data breaches
- **Malicious Insiders**: Compromised user accounts, privilege escalation
- **Tenant Users**: Cross-tenant data access, unauthorized API usage
- **System Administrators**: Abuse of administrative privileges

#### Attack Vectors
```mermaid
graph TD
    A[Attack Vectors] --> B[Authentication Bypass]
    A --> C[Authorization Bypass]
    A --> D[Data Injection]
    A --> E[Cross-Tenant Access]
    A --> F[API Abuse]
    A --> G[System Compromise]
    
    B --> B1[Weak JWT Validation]
    B --> B2[Token Replay Attacks]
    B --> B3[Credential Stuffing]
    
    C --> C1[Privilege Escalation]
    C --> C2[Role Manipulation]
    C --> C3[Permission Bypass]
    
    D --> D1[NoSQL Injection]
    D --> D2[XSS Attacks]
    D --> D3[CSRF Attacks]
    
    E --> E1[Tenant ID Manipulation]
    E --> E2[Data Leakage]
    E --> E3[Resource Sharing Abuse]
    
    F --> F1[Rate Limit Bypass]
    F --> F2[DDoS Attacks]
    F --> F3[Resource Exhaustion]
    
    G --> G1[Infrastructure Compromise]
    G --> G2[Supply Chain Attacks]
    G --> G3[Configuration Vulnerabilities]
```

#### Risk Assessment Matrix
```typescript
interface ThreatRisk {
  threat: string;
  likelihood: 'Low' | 'Medium' | 'High';
  impact: 'Low' | 'Medium' | 'High';
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigation: string[];
}

const threatAssessment: ThreatRisk[] = [
  {
    threat: 'Cross-tenant data access',
    likelihood: 'Medium',
    impact: 'High',
    riskLevel: 'High',
    mitigation: [
      'Strict tenant ID validation',
      'Database-level isolation',
      'Audit logging',
      'Regular security testing'
    ]
  },
  {
    threat: 'JWT token compromise',
    likelihood: 'Medium',
    impact: 'High',
    riskLevel: 'High',
    mitigation: [
      'Short token expiration',
      'Token rotation',
      'Secure storage',
      'Anomaly detection'
    ]
  },
  {
    threat: 'NoSQL injection',
    likelihood: 'Low',
    impact: 'High',
    riskLevel: 'Medium',
    mitigation: [
      'Input validation',
      'Parameterized queries',
      'Schema validation',
      'WAF protection'
    ]
  },
  {
    threat: 'API rate limit bypass',
    likelihood: 'High',
    impact: 'Medium',
    riskLevel: 'Medium',
    mitigation: [
      'Multiple rate limiting layers',
      'IP-based limiting',
      'Behavioral analysis',
      'DDoS protection'
    ]
  }
];
```

### 14.4.2 Security Controls

#### Authentication Controls
```typescript
// JWT Security Configuration
const jwtSecurity = {
  algorithm: 'RS256',              // Use asymmetric encryption
  expiresIn: '15m',               // Short access token lifetime
  refreshExpiresIn: '7d',         // Longer refresh token lifetime
  issuer: 'api-gateway',
  audience: 'api-clients',
  clockTolerance: 30,             // 30 seconds clock skew tolerance
  
  // Token validation rules
  validation: {
    validateIssuer: true,
    validateAudience: true,
    validateExpiration: true,
    validateSignature: true,
    requireClaims: ['sub', 'tenantId', 'roles']
  }
};

// Password Security
const passwordSecurity = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfoInPassword: true,
  maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days
  historyCount: 12                   // Remember last 12 passwords
};
```

#### Authorization Controls
```typescript
// Permission Validation
const permissionSecurity = {
  strictMode: true,               // Fail closed on permission errors
  cacheTimeout: 300,              // 5 minutes permission cache
  hierarchicalRoles: true,        // Support role inheritance
  
  // Permission format validation
  permissionPattern: /^[a-z_]+:[a-z_*]+$/,
  
  // Special permissions
  superAdminPermission: '*',
  systemPermissions: [
    'system:admin',
    'tenant:create',
    'tenant:delete'
  ]
};

// Tenant Isolation
const tenantSecurity = {
  strictIsolation: true,          // Enforce tenant boundaries
  validateTenantId: true,         // Always validate tenant context
  auditCrossTenantAccess: true,   // Log any cross-tenant attempts
  
  // Tenant ID validation
  tenantIdSources: ['jwt', 'header', 'query'],
  tenantIdHeader: 'X-Tenant-ID',
  requireTenantId: true
};
```

#### Data Protection Controls
```typescript
// Encryption Configuration
const encryptionSecurity = {
  // Data at rest
  databaseEncryption: {
    enabled: true,
    algorithm: 'AES-256-GCM',
    keyRotationDays: 90
  },
  
  // Data in transit
  tlsConfig: {
    minVersion: 'TLSv1.2',
    cipherSuites: [
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256'
    ],
    requireSNI: true
  },
  
  // Sensitive data handling
  piiEncryption: {
    fields: ['email', 'phone', 'address'],
    algorithm: 'AES-256-CBC',
    keyDerivation: 'PBKDF2'
  }
};

// Data Retention
const dataRetention = {
  auditLogs: 90 * 24 * 60 * 60 * 1000,    // 90 days
  userSessions: 24 * 60 * 60 * 1000,       // 24 hours
  passwordResetTokens: 60 * 60 * 1000,     // 1 hour
  refreshTokens: 7 * 24 * 60 * 60 * 1000,  // 7 days
  
  // Automatic cleanup
  enableAutoCleanup: true,
  cleanupInterval: 24 * 60 * 60 * 1000     // Daily cleanup
};
```

#### Input Validation Controls
```typescript
// Request Validation
const inputValidation = {
  // Schema validation
  enableSchemaValidation: true,
  strictMode: true,
  additionalProperties: false,
  
  // Sanitization rules
  sanitization: {
    removeHtmlTags: true,
    escapeSpecialChars: true,
    normalizeUnicode: true,
    trimWhitespace: true
  },
  
  // Size limits
  limits: {
    maxRequestSize: '1mb',
    maxFieldSize: '100kb',
    maxFields: 100,
    maxArrayLength: 1000
  },
  
  // Content type validation
  allowedContentTypes: [
    'application/json',
    'application/x-www-form-urlencoded',
    'multipart/form-data'
  ]
};

// NoSQL Injection Prevention
const noSqlSecurity = {
  // Prohibited operators
  prohibitedOperators: [
    '$where',
    '$regex',
    '$expr',
    '$function'
  ],
  
  // Type validation
  enforceTypes: true,
  allowedTypes: ['string', 'number', 'boolean', 'object', 'array'],
  
  // Query sanitization
  sanitizeQueries: true,
  maxQueryDepth: 10,
  maxQueryComplexity: 1000
};
```

### 14.4.3 Compliance Guidelines

#### GDPR Compliance
```typescript
// GDPR Implementation
const gdprCompliance = {
  // Data subject rights
  dataSubjectRights: {
    rightToAccess: true,           // Article 15
    rightToRectification: true,    // Article 16
    rightToErasure: true,          // Article 17
    rightToPortability: true,      // Article 20
    rightToRestriction: true,      // Article 18
    rightToObject: true            // Article 21
  },
  
  // Consent management
  consentManagement: {
    explicitConsent: true,
    granularConsent: true,
    consentWithdrawal: true,
    consentLogging: true
  },
  
  // Data processing
  dataProcessing: {
    lawfulBasis: 'consent',        // Article 6
    purposeLimitation: true,       // Article 5(1)(b)
    dataMinimization: true,        // Article 5(1)(c)
    accuracyPrinciple: true,       // Article 5(1)(d)
    storageLimitation: true,       // Article 5(1)(e)
    integrityConfidentiality: true // Article 5(1)(f)
  },
  
  // Breach notification
  breachNotification: {
    authorityNotification: 72,     // Hours to notify authority
    subjectNotification: true,     // Notify affected individuals
    breachLogging: true,           // Maintain breach records
    riskAssessment: true           // Assess breach impact
  }
};
```

#### SOC 2 Compliance
```typescript
// SOC 2 Trust Criteria
const soc2Compliance = {
  // Security
  security: {
    accessControls: true,
    logicalPhysicalAccess: true,
    systemOperations: true,
    changeManagement: true,
    riskMitigation: true
  },
  
  // Availability
  availability: {
    performanceMonitoring: true,
    capacityPlanning: true,
    systemBackup: true,
    disasterRecovery: true,
    incidentResponse: true
  },
  
  // Processing Integrity
  processingIntegrity: {
    dataValidation: true,
    errorHandling: true,
    dataProcessingAccuracy: true,
    systemProcessing: true
  },
  
  // Confidentiality
  confidentiality: {
    dataClassification: true,
    encryptionControls: true,
    accessRestrictions: true,
    dataHandling: true
  },
  
  // Privacy
  privacy: {
    privacyNotice: true,
    consentManagement: true,
    dataCollection: true,
    dataUseDisclosure: true,
    dataRetention: true,
    dataQuality: true,
    monitoringCompliance: true
  }
};
```

#### Security Audit Checklist
```typescript
// Regular Security Audit Items
const securityAuditChecklist = [
  // Authentication & Authorization
  {
    category: 'Authentication',
    items: [
      'JWT token validation is working correctly',
      'Token expiration is enforced',
      'Refresh token rotation is implemented',
      'Failed login attempts are logged and limited',
      'Password policies are enforced'
    ]
  },
  
  // Data Protection
  {
    category: 'Data Protection',
    items: [
      'Tenant data isolation is maintained',
      'Sensitive data is encrypted at rest',
      'TLS is enforced for all communications',
      'PII is properly protected and anonymized',
      'Data retention policies are followed'
    ]
  },
  
  // Access Control
  {
    category: 'Access Control',
    items: [
      'Role-based permissions are correctly enforced',
      'Principle of least privilege is applied',
      'Administrative access is properly controlled',
      'Cross-tenant access is prevented',
      'Permission changes are audited'
    ]
  },
  
  // System Security
  {
    category: 'System Security',
    items: [
      'All dependencies are up to date',
      'Security headers are properly configured',
      'Rate limiting is effective',
      'Input validation prevents injection attacks',
      'Error messages don\'t leak sensitive information'
    ]
  },
  
  // Monitoring & Logging
  {
    category: 'Monitoring',
    items: [
      'All security events are logged',
      'Audit logs are complete and tamper-proof',
      'Anomaly detection is working',
      'Security alerts are properly configured',
      'Log retention meets compliance requirements'
    ]
  }
];
```

---

*This appendices section provides comprehensive reference material for configuration, API usage, database design, and security implementation. It serves as a quick reference guide for developers, administrators, and security teams working with the Multi-Tenant API Gateway system.* 