# API Documentation

## 9.1 OpenAPI/Swagger Specification

### 9.1.1 API Endpoint Documentation

Complete OpenAPI 3.0 specification for the Multi-Tenant API Gateway.

```yaml
# openapi.yaml
openapi: 3.0.3
info:
  title: Multi-Tenant API Gateway
  description: |
    A secure, scalable API Gateway with multi-tenant support, role-based access control,
    and comprehensive authentication/authorization features.
    
    ## Authentication
    This API uses JWT Bearer tokens for authentication. Include the token in the Authorization header:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
    
    ## Multi-Tenancy
    All requests must include a valid tenant context. The tenant is identified through:
    - JWT token claims (preferred)
    - X-Tenant-ID header (fallback)
    
    ## Rate Limiting
    API requests are rate-limited per tenant and user. Rate limit headers are included in responses:
    - X-RateLimit-Limit: Request limit per time window
    - X-RateLimit-Remaining: Remaining requests in current window
    - X-RateLimit-Reset: Time when the rate limit resets
  version: 1.0.0
  contact:
    name: API Gateway Team
    email: support@apigateway.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: https://api.gateway.com/v1
    description: Production server
  - url: https://staging-api.gateway.com/v1
    description: Staging server
  - url: http://localhost:8000/v1
    description: Development server

security:
  - BearerAuth: []

paths:
  # Authentication Endpoints
  /auth/login:
    post:
      tags:
        - Authentication
      summary: User login
      description: Authenticate user and return JWT token
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
                password:
                  type: string
                  format: password
                  example: SecurePassword123!
                tenantId:
                  type: string
                  format: uuid
                  example: 123e4567-e89b-12d3-a456-426614174000
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
                  refreshToken:
                    type: string
                    example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
                  expiresIn:
                    type: integer
                    example: 3600
                  user:
                    $ref: '#/components/schemas/User'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '400':
          $ref: '#/components/responses/BadRequest'

  /auth/refresh:
    post:
      tags:
        - Authentication
      summary: Refresh JWT token
      description: Get a new JWT token using refresh token
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - refreshToken
              properties:
                refreshToken:
                  type: string
                  example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
      responses:
        '200':
          description: Token refreshed successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                  expiresIn:
                    type: integer
        '401':
          $ref: '#/components/responses/Unauthorized'

  /auth/logout:
    post:
      tags:
        - Authentication
      summary: User logout
      description: Invalidate current JWT token
      responses:
        '200':
          description: Logout successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Logout successful

  # Tenant Management Endpoints
  /tenants:
    get:
      tags:
        - Tenants
      summary: List tenants
      description: Get list of tenants (superadmin only)
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
        - name: status
          in: query
          schema:
            type: string
            enum: [active, inactive, suspended]
        - name: search
          in: query
          schema:
            type: string
      responses:
        '200':
          description: List of tenants
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/Tenant'
                  pagination:
                    $ref: '#/components/schemas/Pagination'
        '403':
          $ref: '#/components/responses/Forbidden'

    post:
      tags:
        - Tenants
      summary: Create tenant
      description: Create a new tenant (superadmin only)
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TenantCreate'
      responses:
        '201':
          description: Tenant created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Tenant'
        '400':
          $ref: '#/components/responses/BadRequest'
        '403':
          $ref: '#/components/responses/Forbidden'

  /tenants/{tenantId}:
    get:
      tags:
        - Tenants
      summary: Get tenant details
      description: Get detailed information about a specific tenant
      parameters:
        - name: tenantId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Tenant details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Tenant'
        '404':
          $ref: '#/components/responses/NotFound'

    put:
      tags:
        - Tenants
      summary: Update tenant
      description: Update tenant information (superadmin only)
      parameters:
        - name: tenantId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TenantUpdate'
      responses:
        '200':
          description: Tenant updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Tenant'
        '400':
          $ref: '#/components/responses/BadRequest'
        '404':
          $ref: '#/components/responses/NotFound'

    delete:
      tags:
        - Tenants
      summary: Delete tenant
      description: Delete a tenant (superadmin only)
      parameters:
        - name: tenantId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '204':
          description: Tenant deleted successfully
        '404':
          $ref: '#/components/responses/NotFound'

  # Role Management Endpoints
  /roles:
    get:
      tags:
        - Roles
      summary: List roles
      description: Get list of roles for current tenant
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
      responses:
        '200':
          description: List of roles
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/Role'
                  pagination:
                    $ref: '#/components/schemas/Pagination'

    post:
      tags:
        - Roles
      summary: Create role
      description: Create a new role for current tenant
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RoleCreate'
      responses:
        '201':
          description: Role created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Role'
        '400':
          $ref: '#/components/responses/BadRequest'

  /roles/{roleId}:
    get:
      tags:
        - Roles
      summary: Get role details
      description: Get detailed information about a specific role
      parameters:
        - name: roleId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Role details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Role'
        '404':
          $ref: '#/components/responses/NotFound'

    put:
      tags:
        - Roles
      summary: Update role
      description: Update role information
      parameters:
        - name: roleId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RoleUpdate'
      responses:
        '200':
          description: Role updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Role'
        '400':
          $ref: '#/components/responses/BadRequest'
        '404':
          $ref: '#/components/responses/NotFound'

    delete:
      tags:
        - Roles
      summary: Delete role
      description: Delete a role
      parameters:
        - name: roleId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '204':
          description: Role deleted successfully
        '404':
          $ref: '#/components/responses/NotFound'

  # User Management Endpoints
  /users:
    get:
      tags:
        - Users
      summary: List users
      description: Get list of users for current tenant
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
        - name: role
          in: query
          schema:
            type: string
        - name: status
          in: query
          schema:
            type: string
            enum: [active, inactive, pending]
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
                  pagination:
                    $ref: '#/components/schemas/Pagination'

    post:
      tags:
        - Users
      summary: Create user
      description: Create a new user for current tenant
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserCreate'
      responses:
        '201':
          description: User created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          $ref: '#/components/responses/BadRequest'

  /users/{userId}:
    get:
      tags:
        - Users
      summary: Get user details
      description: Get detailed information about a specific user
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: User details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '404':
          $ref: '#/components/responses/NotFound'

    put:
      tags:
        - Users
      summary: Update user
      description: Update user information
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserUpdate'
      responses:
        '200':
          description: User updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          $ref: '#/components/responses/BadRequest'
        '404':
          $ref: '#/components/responses/NotFound'

  /users/{userId}/roles:
    post:
      tags:
        - Users
      summary: Assign role to user
      description: Assign a role to a user
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - roleId
              properties:
                roleId:
                  type: string
                  format: uuid
      responses:
        '200':
          description: Role assigned successfully
        '400':
          $ref: '#/components/responses/BadRequest'
        '404':
          $ref: '#/components/responses/NotFound'

    delete:
      tags:
        - Users
      summary: Remove role from user
      description: Remove a role from a user
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            format: uuid
        - name: roleId
          in: query
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Role removed successfully
        '404':
          $ref: '#/components/responses/NotFound'

  # Health Check
  /health:
    get:
      tags:
        - System
      summary: Health check
      description: Check system health status
      security: []
      responses:
        '200':
          description: System is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthStatus'
        '503':
          description: System is unhealthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthStatus'

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
          example: 123e4567-e89b-12d3-a456-426614174000
        email:
          type: string
          format: email
          example: user@example.com
        firstName:
          type: string
          example: John
        lastName:
          type: string
          example: Doe
        tenantId:
          type: string
          format: uuid
          example: 123e4567-e89b-12d3-a456-426614174000
        roles:
          type: array
          items:
            $ref: '#/components/schemas/Role'
        status:
          type: string
          enum: [active, inactive, pending]
          example: active
        createdAt:
          type: string
          format: date-time
          example: 2023-01-01T00:00:00Z
        updatedAt:
          type: string
          format: date-time
          example: 2023-01-01T00:00:00Z

    UserCreate:
      type: object
      required:
        - email
        - firstName
        - lastName
        - password
      properties:
        email:
          type: string
          format: email
        firstName:
          type: string
          minLength: 1
          maxLength: 50
        lastName:
          type: string
          minLength: 1
          maxLength: 50
        password:
          type: string
          minLength: 8
        roleIds:
          type: array
          items:
            type: string
            format: uuid

    UserUpdate:
      type: object
      properties:
        firstName:
          type: string
          minLength: 1
          maxLength: 50
        lastName:
          type: string
          minLength: 1
          maxLength: 50
        status:
          type: string
          enum: [active, inactive, pending]

    Tenant:
      type: object
      properties:
        id:
          type: string
          format: uuid
          example: 123e4567-e89b-12d3-a456-426614174000
        name:
          type: string
          example: Acme Corporation
        domain:
          type: string
          example: acme.com
        contactEmail:
          type: string
          format: email
          example: admin@acme.com
        description:
          type: string
          example: Enterprise customer
        status:
          type: string
          enum: [active, inactive, suspended]
          example: active
        settings:
          type: object
          properties:
            maxUsers:
              type: integer
              example: 100
            rateLimit:
              type: integer
              example: 1000
            features:
              type: array
              items:
                type: string
              example: [api_access, webhook_support]
            allowedDomains:
              type: array
              items:
                type: string
              example: [acme.com, app.acme.com]
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    TenantCreate:
      type: object
      required:
        - name
        - contactEmail
      properties:
        name:
          type: string
          minLength: 2
          maxLength: 100
        domain:
          type: string
          pattern: '^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        contactEmail:
          type: string
          format: email
        description:
          type: string
          maxLength: 500
        settings:
          type: object
          properties:
            maxUsers:
              type: integer
              minimum: 1
              maximum: 10000
              default: 100
            rateLimit:
              type: integer
              minimum: 10
              maximum: 10000
              default: 1000
            features:
              type: array
              items:
                type: string

    TenantUpdate:
      type: object
      properties:
        name:
          type: string
          minLength: 2
          maxLength: 100
        domain:
          type: string
        contactEmail:
          type: string
          format: email
        description:
          type: string
          maxLength: 500
        status:
          type: string
          enum: [active, inactive, suspended]
        settings:
          type: object

    Role:
      type: object
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
          example: admin
        description:
          type: string
          example: Administrator role with full access
        tenantId:
          type: string
          format: uuid
        permissions:
          type: array
          items:
            type: string
          example: [read:users, write:users, delete:users]
        isSystem:
          type: boolean
          example: false
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    RoleCreate:
      type: object
      required:
        - name
        - permissions
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 50
          pattern: '^[a-zA-Z0-9_-]+$'
        description:
          type: string
          maxLength: 200
        permissions:
          type: array
          items:
            type: string
            pattern: '^[a-zA-Z0-9:_-]+$'

    RoleUpdate:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 50
        description:
          type: string
          maxLength: 200
        permissions:
          type: array
          items:
            type: string

    Pagination:
      type: object
      properties:
        page:
          type: integer
          example: 1
        limit:
          type: integer
          example: 20
        total:
          type: integer
          example: 100
        totalPages:
          type: integer
          example: 5
        hasNext:
          type: boolean
          example: true
        hasPrev:
          type: boolean
          example: false

    HealthStatus:
      type: object
      properties:
        status:
          type: string
          enum: [healthy, degraded, unhealthy]
          example: healthy
        timestamp:
          type: string
          format: date-time
        version:
          type: string
          example: 1.0.0
        services:
          type: object
          properties:
            database:
              type: object
              properties:
                status:
                  type: string
                  enum: [healthy, unhealthy]
                error:
                  type: string
            cache:
              type: object
              properties:
                status:
                  type: string
                  enum: [healthy, unhealthy]
                error:
                  type: string
            cognito:
              type: object
              properties:
                status:
                  type: string
                  enum: [healthy, unhealthy]
                error:
                  type: string

    Error:
      type: object
      properties:
        error:
          type: object
          properties:
            code:
              type: string
              example: VALIDATION_ERROR
            message:
              type: string
              example: Validation failed
            details:
              type: object
            timestamp:
              type: string
              format: date-time
            requestId:
              type: string
              format: uuid

  responses:
    BadRequest:
      description: Bad request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: VALIDATION_ERROR
              message: Validation failed
              details:
                - field: email
                  message: Invalid email format
              timestamp: 2023-01-01T00:00:00Z
              requestId: 123e4567-e89b-12d3-a456-426614174000

    Unauthorized:
      description: Unauthorized
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: AUTHENTICATION_ERROR
              message: Invalid or expired token
              timestamp: 2023-01-01T00:00:00Z
              requestId: 123e4567-e89b-12d3-a456-426614174000

    Forbidden:
      description: Forbidden
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: AUTHORIZATION_ERROR
              message: Insufficient permissions
              timestamp: 2023-01-01T00:00:00Z
              requestId: 123e4567-e89b-12d3-a456-426614174000

    NotFound:
      description: Resource not found
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: NOT_FOUND
              message: Resource not found
              timestamp: 2023-01-01T00:00:00Z
              requestId: 123e4567-e89b-12d3-a456-426614174000

    RateLimit:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
          description: Request limit per time window
        X-RateLimit-Remaining:
          schema:
            type: integer
          description: Remaining requests in current window
        X-RateLimit-Reset:
          schema:
            type: integer
          description: Time when the rate limit resets (Unix timestamp)
        Retry-After:
          schema:
            type: integer
          description: Seconds to wait before retrying
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: RATE_LIMIT_EXCEEDED
              message: Rate limit exceeded
              details:
                retryAfter: 60
              timestamp: 2023-01-01T00:00:00Z
              requestId: 123e4567-e89b-12d3-a456-426614174000
```

### 9.1.2 Request/Response Schemas

Detailed schemas for complex request and response objects.

```typescript
// types/api.ts
export interface ApiResponse<T = any> {
  data?: T;
  error?: ApiError;
  pagination?: Pagination;
}

export interface ApiError {
  code: string;
  message: string;
  details?: any;
  timestamp: string;
  requestId: string;
}

export interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Authentication Types
export interface LoginRequest {
  email: string;
  password: string;
  tenantId?: string;
}

export interface LoginResponse {
  token: string;
  refreshToken: string;
  expiresIn: number;
  user: User;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  token: string;
  expiresIn: number;
}

// Tenant Types
export interface TenantSettings {
  maxUsers: number;
  rateLimit: number;
  features: string[];
  allowedDomains: string[];
  customization?: {
    logo?: string;
    primaryColor?: string;
    theme?: string;
  };
}

export interface Tenant {
  id: string;
  name: string;
  domain?: string;
  contactEmail: string;
  description?: string;
  status: 'active' | 'inactive' | 'suspended';
  settings: TenantSettings;
  createdAt: string;
  updatedAt: string;
}

export interface TenantCreateRequest {
  name: string;
  domain?: string;
  contactEmail: string;
  description?: string;
  settings?: Partial<TenantSettings>;
}

export interface TenantUpdateRequest {
  name?: string;
  domain?: string;
  contactEmail?: string;
  description?: string;
  status?: 'active' | 'inactive' | 'suspended';
  settings?: Partial<TenantSettings>;
}

// Role Types
export interface Role {
  id: string;
  name: string;
  description?: string;
  tenantId: string;
  permissions: string[];
  isSystem: boolean;
  userCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface RoleCreateRequest {
  name: string;
  description?: string;
  permissions: string[];
}

export interface RoleUpdateRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

// User Types
export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  tenantId: string;
  roles: Role[];
  status: 'active' | 'inactive' | 'pending';
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface UserCreateRequest {
  email: string;
  firstName: string;
  lastName: string;
  password: string;
  roleIds?: string[];
}

export interface UserUpdateRequest {
  firstName?: string;
  lastName?: string;
  status?: 'active' | 'inactive' | 'pending';
}

// Health Check Types
export interface ServiceHealth {
  status: 'healthy' | 'unhealthy';
  error?: string;
  responseTime?: number;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  services: {
    database: ServiceHealth;
    cache: ServiceHealth;
    cognito: ServiceHealth;
  };
  degradation?: Record<string, any>;
}
```

### 9.1.3 Authentication Examples

Comprehensive authentication flow examples.

```javascript
// Authentication Flow Examples

// 1. User Login
const loginExample = async () => {
  const response = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: 'user@example.com',
      password: 'SecurePassword123!',
      tenantId: '123e4567-e89b-12d3-a456-426614174000'
    })
  });

  if (response.ok) {
    const data = await response.json();
    // Store tokens securely
    localStorage.setItem('accessToken', data.token);
    localStorage.setItem('refreshToken', data.refreshToken);
    
    console.log('Login successful:', data.user);
  } else {
    const error = await response.json();
    console.error('Login failed:', error.error.message);
  }
};

// 2. Making Authenticated Requests
const makeAuthenticatedRequest = async () => {
  const token = localStorage.getItem('accessToken');
  
  const response = await fetch('/api/v1/users', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (response.ok) {
    const data = await response.json();
    console.log('Users:', data.data);
  } else if (response.status === 401) {
    // Token expired, try to refresh
    await refreshToken();
    // Retry the request
    return makeAuthenticatedRequest();
  }
};

// 3. Token Refresh
const refreshToken = async () => {
  const refreshToken = localStorage.getItem('refreshToken');
  
  const response = await fetch('/api/v1/auth/refresh', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      refreshToken: refreshToken
    })
  });

  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('accessToken', data.token);
    return data.token;
  } else {
    // Refresh failed, redirect to login
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }
};

// 4. Automatic Token Refresh
class ApiClient {
  constructor() {
    this.baseURL = '/api/v1';
    this.token = localStorage.getItem('accessToken');
    this.refreshToken = localStorage.getItem('refreshToken');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    if (this.token) {
      config.headers.Authorization = `Bearer ${this.token}`;
    }

    let response = await fetch(url, config);

    // Handle token refresh
    if (response.status === 401 && this.refreshToken) {
      const newToken = await this.refreshAccessToken();
      if (newToken) {
        config.headers.Authorization = `Bearer ${newToken}`;
        response = await fetch(url, config);
      }
    }

    return response;
  }

  async refreshAccessToken() {
    try {
      const response = await fetch(`${this.baseURL}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: this.refreshToken
        })
      });

      if (response.ok) {
        const data = await response.json();
        this.token = data.token;
        localStorage.setItem('accessToken', data.token);
        return data.token;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }

    // Refresh failed
    this.logout();
    return null;
  }

  logout() {
    this.token = null;
    this.refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
  }
}

// Usage
const apiClient = new ApiClient();

// Get users
const users = await apiClient.request('/users');

// Create user
const newUser = await apiClient.request('/users', {
  method: 'POST',
  body: JSON.stringify({
    email: 'newuser@example.com',
    firstName: 'John',
    lastName: 'Doe',
    password: 'SecurePassword123!'
  })
});
```

## 9.2 Integration Guides

### 9.2.1 Client SDK Documentation

JavaScript/TypeScript SDK for easy integration.

```typescript
// api-gateway-sdk.ts
export class ApiGatewaySDK {
  private baseURL: string;
  private token: string | null = null;
  private refreshToken: string | null = null;
  private tenantId: string | null = null;

  constructor(config: {
    baseURL: string;
    tenantId?: string;
  }) {
    this.baseURL = config.baseURL;
    this.tenantId = config.tenantId || null;
  }

  // Authentication methods
  async login(email: string, password: string, tenantId?: string): Promise<LoginResponse> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: {
        email,
        password,
        tenantId: tenantId || this.tenantId
      }
    });

    if (response.token) {
      this.setTokens(response.token, response.refreshToken);
    }

    return response;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.clearTokens();
    }
  }

  setTokens(accessToken: string, refreshToken: string): void {
    this.token = accessToken;
    this.refreshToken = refreshToken;
  }

  clearTokens(): void {
    this.token = null;
    this.refreshToken = null;
  }

  // Tenant methods
  async getTenants(params?: {
    page?: number;
    limit?: number;
    status?: string;
    search?: string;
  }): Promise<ApiResponse<Tenant[]>> {
    return this.request('/tenants', { params });
  }

  async getTenant(tenantId: string): Promise<Tenant> {
    return this.request(`/tenants/${tenantId}`);
  }

  async createTenant(data: TenantCreateRequest): Promise<Tenant> {
    return this.request('/tenants', {
      method: 'POST',
      body: data
    });
  }

  async updateTenant(tenantId: string, data: TenantUpdateRequest): Promise<Tenant> {
    return this.request(`/tenants/${tenantId}`, {
      method: 'PUT',
      body: data
    });
  }

  async deleteTenant(tenantId: string): Promise<void> {
    return this.request(`/tenants/${tenantId}`, {
      method: 'DELETE'
    });
  }

  // Role methods
  async getRoles(params?: {
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<Role[]>> {
    return this.request('/roles', { params });
  }

  async getRole(roleId: string): Promise<Role> {
    return this.request(`/roles/${roleId}`);
  }

  async createRole(data: RoleCreateRequest): Promise<Role> {
    return this.request('/roles', {
      method: 'POST',
      body: data
    });
  }

  async updateRole(roleId: string, data: RoleUpdateRequest): Promise<Role> {
    return this.request(`/roles/${roleId}`, {
      method: 'PUT',
      body: data
    });
  }

  async deleteRole(roleId: string): Promise<void> {
    return this.request(`/roles/${roleId}`, {
      method: 'DELETE'
    });
  }

  // User methods
  async getUsers(params?: {
    page?: number;
    limit?: number;
    role?: string;
    status?: string;
  }): Promise<ApiResponse<User[]>> {
    return this.request('/users', { params });
  }

  async getUser(userId: string): Promise<User> {
    return this.request(`/users/${userId}`);
  }

  async createUser(data: UserCreateRequest): Promise<User> {
    return this.request('/users', {
      method: 'POST',
      body: data
    });
  }

  async updateUser(userId: string, data: UserUpdateRequest): Promise<User> {
    return this.request(`/users/${userId}`, {
      method: 'PUT',
      body: data
    });
  }

  async assignRole(userId: string, roleId: string): Promise<void> {
    return this.request(`/users/${userId}/roles`, {
      method: 'POST',
      body: { roleId }
    });
  }

  async removeRole(userId: string, roleId: string): Promise<void> {
    return this.request(`/users/${userId}/roles`, {
      method: 'DELETE',
      params: { roleId }
    });
  }

  // Health check
  async getHealth(): Promise<HealthStatus> {
    return this.request('/health');
  }

  // Private methods
  private async request(endpoint: string, options: {
    method?: string;
    body?: any;
    params?: Record<string, any>;
    headers?: Record<string, string>;
  } = {}): Promise<any> {
    const { method = 'GET', body, params, headers = {} } = options;

    // Build URL with query parameters
    const url = new URL(`${this.baseURL}${endpoint}`);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    // Build request config
    const config: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };

    // Add authentication header
    if (this.token) {
      config.headers = {
        ...config.headers,
        'Authorization': `Bearer ${this.token}`
      };
    }

    // Add tenant header if available
    if (this.tenantId) {
      config.headers = {
        ...config.headers,
        'X-Tenant-ID': this.tenantId
      };
    }

    // Add body for non-GET requests
    if (body && method !== 'GET') {
      config.body = JSON.stringify(body);
    }

    let response = await fetch(url.toString(), config);

    // Handle token refresh
    if (response.status === 401 && this.refreshToken) {
      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        // Retry the request with new token
        config.headers = {
          ...config.headers,
          'Authorization': `Bearer ${this.token}`
        };
        response = await fetch(url.toString(), config);
      }
    }

    // Handle response
    if (!response.ok) {
      const error = await response.json();
      throw new ApiError(error.error);
    }

    // Return empty for 204 No Content
    if (response.status === 204) {
      return;
    }

    return response.json();
  }

  private async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken) return false;

    try {
      const response = await fetch(`${this.baseURL}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: this.refreshToken
        })
      });

      if (response.ok) {
        const data = await response.json();
        this.token = data.token;
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }

    this.clearTokens();
    return false;
  }
}

// Error class
export class ApiError extends Error {
  public code: string;
  public details?: any;
  public timestamp: string;
  public requestId: string;

  constructor(error: ApiError) {
    super(error.message);
    this.code = error.code;
    this.details = error.details;
    this.timestamp = error.timestamp;
    this.requestId = error.requestId;
  }
}

// Usage example
const sdk = new ApiGatewaySDK({
  baseURL: 'https://api.gateway.com/v1',
  tenantId: '123e4567-e89b-12d3-a456-426614174000'
});

// Login
await sdk.login('user@example.com', 'password');

// Get users
const users = await sdk.getUsers({ page: 1, limit: 20 });

// Create role
const role = await sdk.createRole({
  name: 'editor',
  description: 'Content editor role',
  permissions: ['read:content', 'write:content']
});
```

### 9.2.2 Authentication Flow Examples

Complete authentication flow implementations for different scenarios.

```javascript
// React Hook for Authentication
import { useState, useEffect, useContext, createContext } from 'react';
import { ApiGatewaySDK } from './api-gateway-sdk';

const AuthContext = createContext();

export const AuthProvider = ({ children, config }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sdk] = useState(() => new ApiGatewaySDK(config));

  useEffect(() => {
    // Check for existing tokens on mount
    const token = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (token && refreshToken) {
      sdk.setTokens(token, refreshToken);
      // Validate token by making a request
      validateToken();
    } else {
      setLoading(false);
    }
  }, []);

  const validateToken = async () => {
    try {
      // Make a request to validate the token
      const health = await sdk.getHealth();
      // If successful, token is valid
      setLoading(false);
    } catch (error) {
      // Token is invalid, clear it
      logout();
    }
  };

  const login = async (email, password, tenantId) => {
    try {
      const response = await sdk.login(email, password, tenantId);
      
      // Store tokens
      localStorage.setItem('accessToken', response.token);
      localStorage.setItem('refreshToken', response.refreshToken);
      
      setUser(response.user);
      return response;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    sdk.logout();
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    setLoading(false);
  };

  const value = {
    user,
    loading,
    login,
    logout,
    sdk,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Vue.js Composition API
import { ref, reactive, computed } from 'vue';
import { ApiGatewaySDK } from './api-gateway-sdk';

export function useAuth(config) {
  const user = ref(null);
  const loading = ref(true);
  const sdk = new ApiGatewaySDK(config);

  const isAuthenticated = computed(() => !!user.value);

  const login = async (email, password, tenantId) => {
    try {
      const response = await sdk.login(email, password, tenantId);
      
      localStorage.setItem('accessToken', response.token);
      localStorage.setItem('refreshToken', response.refreshToken);
      
      user.value = response.user;
      return response;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    sdk.logout();
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    user.value = null;
  };

  const init = async () => {
    const token = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (token && refreshToken) {
      sdk.setTokens(token, refreshToken);
      try {
        await sdk.getHealth();
      } catch (error) {
        logout();
      }
    }
    
    loading.value = false;
  };

  return {
    user: readonly(user),
    loading: readonly(loading),
    isAuthenticated,
    login,
    logout,
    init,
    sdk
  };
}

// Node.js Server-Side Authentication
class ServerAuthManager {
  constructor(config) {
    this.sdk = new ApiGatewaySDK(config);
    this.tokenCache = new Map();
  }

  async authenticateRequest(req, res, next) {
    try {
      const token = this.extractToken(req);
      if (!token) {
        return res.status(401).json({
          error: {
            code: 'AUTHENTICATION_ERROR',
            message: 'No token provided'
          }
        });
      }

      // Check cache first
      let user = this.tokenCache.get(token);
      if (!user) {
        // Validate token with API Gateway
        user = await this.validateToken(token);
        if (user) {
          // Cache for 5 minutes
          this.tokenCache.set(token, user);
          setTimeout(() => this.tokenCache.delete(token), 5 * 60 * 1000);
        }
      }

      if (!user) {
        return res.status(401).json({
          error: {
            code: 'AUTHENTICATION_ERROR',
            message: 'Invalid token'
          }
        });
      }

      req.user = user;
      next();
    } catch (error) {
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Authentication error'
        }
      });
    }
  }

  extractToken(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return null;
  }

  async validateToken(token) {
    try {
      // Set token and make a request to validate
      this.sdk.setTokens(token, '');
      const health = await this.sdk.getHealth();
      
      // If successful, extract user info from token
      const payload = this.decodeJWT(token);
      return {
        id: payload.sub,
        email: payload.email,
        tenantId: payload.tenantId,
        roles: payload.roles,
        permissions: payload.permissions
      };
    } catch (error) {
      return null;
    }
  }

  decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    
    const payload = parts[1];
    const decoded = Buffer.from(payload, 'base64').toString('utf8');
    return JSON.parse(decoded);
  }
}

// Express.js middleware usage
const authManager = new ServerAuthManager({
  baseURL: 'https://api.gateway.com/v1'
});

app.use('/api/protected', authManager.authenticateRequest.bind(authManager));
```

### 9.2.3 Common Integration Patterns

Frequently used integration patterns and best practices.

```javascript
// 1. Retry Logic with Exponential Backoff
class RetryableApiClient {
  constructor(sdk, options = {}) {
    this.sdk = sdk;
    this.maxRetries = options.maxRetries || 3;
    this.baseDelay = options.baseDelay || 1000;
    this.maxDelay = options.maxDelay || 10000;
  }

  async requestWithRetry(operation, ...args) {
    let lastError;
    
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        return await operation.apply(this.sdk, args);
      } catch (error) {
        lastError = error;
        
        // Don't retry on authentication or validation errors
        if (error.code === 'AUTHENTICATION_ERROR' || 
            error.code === 'VALIDATION_ERROR' ||
            error.code === 'AUTHORIZATION_ERROR') {
          throw error;
        }
        
        if (attempt < this.maxRetries) {
          const delay = Math.min(
            this.baseDelay * Math.pow(2, attempt),
            this.maxDelay
          );
          await this.sleep(delay);
        }
      }
    }
    
    throw lastError;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage
const retryableClient = new RetryableApiClient(sdk);
const users = await retryableClient.requestWithRetry(sdk.getUsers, { page: 1 });

// 2. Batch Operations
class BatchApiClient {
  constructor(sdk, options = {}) {
    this.sdk = sdk;
    this.batchSize = options.batchSize || 10;
    this.concurrency = options.concurrency || 3;
  }

  async batchCreateUsers(users) {
    const results = [];
    const errors = [];
    
    for (let i = 0; i < users.length; i += this.batchSize) {
      const batch = users.slice(i, i + this.batchSize);
      const batchPromises = batch.map(async (user, index) => {
        try {
          const result = await this.sdk.createUser(user);
          return { index: i + index, result };
        } catch (error) {
          return { index: i + index, error };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      
      batchResults.forEach(({ index, result, error }) => {
        if (error) {
          errors.push({ index, error, user: users[index] });
        } else {
          results.push({ index, result });
        }
      });
    }
    
    return { results, errors };
  }

  async batchUpdateUsers(updates) {
    const semaphore = new Semaphore(this.concurrency);
    
    const promises = updates.map(async ({ userId, data }) => {
      await semaphore.acquire();
      try {
        return await this.sdk.updateUser(userId, data);
      } finally {
        semaphore.release();
      }
    });
    
    return Promise.allSettled(promises);
  }
}

// Simple semaphore implementation
class Semaphore {
  constructor(max) {
    this.max = max;
    this.current = 0;
    this.queue = [];
  }

  async acquire() {
    if (this.current < this.max) {
      this.current++;
      return;
    }
    
    return new Promise(resolve => {
      this.queue.push(resolve);
    });
  }

  release() {
    this.current--;
    if (this.queue.length > 0) {
      this.current++;
      const resolve = this.queue.shift();
      resolve();
    }
  }
}

// 3. Real-time Updates with WebSockets
class RealtimeApiClient {
  constructor(sdk, wsUrl) {
    this.sdk = sdk;
    this.wsUrl = wsUrl;
    this.ws = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      
      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
        
        // Authenticate WebSocket connection
        this.ws.send(JSON.stringify({
          type: 'auth',
          token: this.sdk.token
        }));
        
        resolve();
      };
      
      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      
      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.attemptReconnect();
      };
      
      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        reject(error);
      };
    });
  }

  handleMessage(message) {
    const { type, data } = message;
    const listeners = this.listeners.get(type) || [];
    listeners.forEach(callback => callback(data));
  }

  subscribe(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, []);
    }
    this.listeners.get(eventType).push(callback);
    
    // Send subscription message
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'subscribe',
        eventType
      }));
    }
  }

  unsubscribe(eventType, callback) {
    const listeners = this.listeners.get(eventType) || [];
    const index = listeners.indexOf(callback);
    if (index > -1) {
      listeners.splice(index, 1);
    }
  }

  attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.pow(2, this.reconnectAttempts) * 1000;
      
      setTimeout(() => {
        console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        this.connect().catch(() => {
          // Reconnection failed, will try again
        });
      }, delay);
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

// Usage
const realtimeClient = new RealtimeApiClient(sdk, 'wss://api.gateway.com/ws');
await realtimeClient.connect();

realtimeClient.subscribe('user.created', (user) => {
  console.log('New user created:', user);
});

realtimeClient.subscribe('role.updated', (role) => {
  console.log('Role updated:', role);
});

// 4. Caching Layer
class CachedApiClient {
  constructor(sdk, options = {}) {
    this.sdk = sdk;
    this.cache = new Map();
    this.defaultTTL = options.defaultTTL || 5 * 60 * 1000; // 5 minutes
    this.maxCacheSize = options.maxCacheSize || 1000;
  }

  async get(key, fetcher, ttl = this.defaultTTL) {
    const cached = this.cache.get(key);
    
    if (cached && Date.now() < cached.expiry) {
      return cached.data;
    }
    
    const data = await fetcher();
    this.set(key, data, ttl);
    return data;
  }

  set(key, data, ttl = this.defaultTTL) {
    // Implement LRU eviction if cache is full
    if (this.cache.size >= this.maxCacheSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.set(key, {
      data,
      expiry: Date.now() + ttl
    });
  }

  invalidate(pattern) {
    for (const key of this.cache.keys()) {
      if (key.includes(pattern)) {
        this.cache.delete(key);
      }
    }
  }

  // Cached methods
  async getUsers(params = {}) {
    const key = `users:${JSON.stringify(params)}`;
    return this.get(key, () => this.sdk.getUsers(params));
  }

  async getUser(userId) {
    const key = `user:${userId}`;
    return this.get(key, () => this.sdk.getUser(userId));
  }

  async getRoles(params = {}) {
    const key = `roles:${JSON.stringify(params)}`;
    return this.get(key, () => this.sdk.getRoles(params));
  }

  // Invalidate cache on mutations
  async createUser(data) {
    const result = await this.sdk.createUser(data);
    this.invalidate('users:');
    return result;
  }

  async updateUser(userId, data) {
    const result = await this.sdk.updateUser(userId, data);
    this.invalidate(`user:${userId}`);
    this.invalidate('users:');
    return result;
  }
}

// Usage
const cachedClient = new CachedApiClient(sdk);
const users = await cachedClient.getUsers({ page: 1 }); // Fetches from API
const usersAgain = await cachedClient.getUsers({ page: 1 }); // Returns from cache
```

## 9.3 Error Reference

### 9.3.1 Error Code Definitions

Complete reference of all error codes and their meanings.

```typescript
// Error Code Reference
export const ERROR_CODES = {
  // Authentication Errors (1000-1099)
  AUTHENTICATION_ERROR: {
    code: 'AUTHENTICATION_ERROR',
    httpStatus: 401,
    description: 'Authentication failed or token is invalid',
    causes: [
      'Invalid credentials',
      'Expired token',
      'Malformed token',
      'Token signature verification failed'
    ],
    solutions: [
      'Check credentials and try again',
      'Refresh the token',
      'Re-authenticate'
    ]
  },

  TOKEN_EXPIRED: {
    code: 'TOKEN_EXPIRED',
    httpStatus: 401,
    description: 'JWT token has expired',
    causes: ['Token TTL exceeded'],
    solutions: ['Use refresh token to get new access token']
  },

  INVALID_TOKEN: {
    code: 'INVALID_TOKEN',
    httpStatus: 401,
    description: 'JWT token is malformed or invalid',
    causes: [
      'Token format is incorrect',
      'Token signature is invalid',
      'Token claims are missing'
    ],
    solutions: ['Re-authenticate to get a valid token']
  },

  // Authorization Errors (1100-1199)
  AUTHORIZATION_ERROR: {
    code: 'AUTHORIZATION_ERROR',
    httpStatus: 403,
    description: 'Insufficient permissions to access resource',
    causes: [
      'User lacks required permissions',
      'Role does not have access to resource',
      'Tenant-level restrictions'
    ],
    solutions: [
      'Contact administrator to grant permissions',
      'Assign appropriate role to user'
    ]
  },

  INSUFFICIENT_PERMISSIONS: {
    code: 'INSUFFICIENT_PERMISSIONS',
    httpStatus: 403,
    description: 'User does not have required permissions',
    causes: ['Missing specific permission for the action'],
    solutions: ['Request permission from tenant administrator']
  },

  TENANT_ACCESS_DENIED: {
    code: 'TENANT_ACCESS_DENIED',
    httpStatus: 403,
    description: 'Access denied for the specified tenant',
    causes: [
      'User not associated with tenant',
      'Tenant is suspended or inactive'
    ],
    solutions: [
      'Verify tenant association',
      'Contact support if tenant is suspended'
    ]
  },

  // Validation Errors (1200-1299)
  VALIDATION_ERROR: {
    code: 'VALIDATION_ERROR',
    httpStatus: 400,
    description: 'Request validation failed',
    causes: [
      'Missing required fields',
      'Invalid field format',
      'Field value out of range'
    ],
    solutions: ['Check request format and field values']
  },

  INVALID_EMAIL: {
    code: 'INVALID_EMAIL',
    httpStatus: 400,
    description: 'Email format is invalid',
    causes: ['Email does not match required format'],
    solutions: ['Provide valid email address']
  },

  INVALID_PASSWORD: {
    code: 'INVALID_PASSWORD',
    httpStatus: 400,
    description: 'Password does not meet requirements',
    causes: [
      'Password too short',
      'Missing required character types',
      'Password is too common'
    ],
    solutions: ['Use password with minimum 8 characters, including uppercase, lowercase, number, and special character']
  },

  // Resource Errors (1300-1399)
  NOT_FOUND: {
    code: 'NOT_FOUND',
    httpStatus: 404,
    description: 'Requested resource not found',
    causes: [
      'Resource ID does not exist',
      'Resource was deleted',
      'User lacks access to resource'
    ],
    solutions: [
      'Verify resource ID',
      'Check if resource exists',
      'Ensure proper permissions'
    ]
  },

  USER_NOT_FOUND: {
    code: 'USER_NOT_FOUND',
    httpStatus: 404,
    description: 'User not found',
    causes: ['User ID does not exist in tenant'],
    solutions: ['Verify user ID and tenant context']
  },

  ROLE_NOT_FOUND: {
    code: 'ROLE_NOT_FOUND',
    httpStatus: 404,
    description: 'Role not found',
    causes: ['Role ID does not exist in tenant'],
    solutions: ['Verify role ID and tenant context']
  },

  TENANT_NOT_FOUND: {
    code: 'TENANT_NOT_FOUND',
    httpStatus: 404,
    description: 'Tenant not found',
    causes: ['Tenant ID does not exist'],
    solutions: ['Verify tenant ID']
  },

  // Conflict Errors (1400-1499)
  CONFLICT: {
    code: 'CONFLICT',
    httpStatus: 409,
    description: 'Resource conflict',
    causes: [
      'Resource already exists',
      'Concurrent modification',
      'Business rule violation'
    ],
    solutions: [
      'Use different identifier',
      'Retry with updated data',
      'Check business constraints'
    ]
  },

  EMAIL_ALREADY_EXISTS: {
    code: 'EMAIL_ALREADY_EXISTS',
    httpStatus: 409,
    description: 'Email address is already registered',
    causes: ['Another user has the same email'],
    solutions: ['Use different email address']
  },

  ROLE_NAME_EXISTS: {
    code: 'ROLE_NAME_EXISTS',
    httpStatus: 409,
    description: 'Role name already exists in tenant',
    causes: ['Another role has the same name'],
    solutions: ['Use different role name']
  },

  // Rate Limiting Errors (1500-1599)
  RATE_LIMIT_EXCEEDED: {
    code: 'RATE_LIMIT_EXCEEDED',
    httpStatus: 429,
    description: 'Rate limit exceeded',
    causes: [
      'Too many requests in time window',
      'Tenant rate limit reached',
      'User rate limit reached'
    ],
    solutions: [
      'Wait before making more requests',
      'Implement exponential backoff',
      'Contact support for rate limit increase'
    ]
  },

  // System Errors (1600-1699)
  INTERNAL_ERROR: {
    code: 'INTERNAL_ERROR',
    httpStatus: 500,
    description: 'Internal server error',
    causes: [
      'Database connection failure',
      'External service unavailable',
      'Unexpected system error'
    ],
    solutions: [
      'Retry the request',
      'Contact support if error persists'
    ]
  },

  DATABASE_ERROR: {
    code: 'DATABASE_ERROR',
    httpStatus: 500,
    description: 'Database operation failed',
    causes: [
      'Database connection lost',
      'Query timeout',
      'Database constraint violation'
    ],
    solutions: ['Retry the request after a short delay']
  },

  EXTERNAL_SERVICE_ERROR: {
    code: 'EXTERNAL_SERVICE_ERROR',
    httpStatus: 502,
    description: 'External service error',
    causes: [
      'AWS Cognito unavailable',
      'Third-party service timeout',
      'Network connectivity issues'
    ],
    solutions: ['Retry the request or contact support']
  },

  SERVICE_UNAVAILABLE: {
    code: 'SERVICE_UNAVAILABLE',
    httpStatus: 503,
    description: 'Service temporarily unavailable',
    causes: [
      'System maintenance',
      'High load',
      'Circuit breaker open'
    ],
    solutions: ['Wait and retry later']
  }
};

// Error handling utility
export class ErrorHandler {
  static getErrorInfo(code: string) {
    return ERROR_CODES[code] || ERROR_CODES.INTERNAL_ERROR;
  }

  static formatError(error: any) {
    const errorInfo = this.getErrorInfo(error.code);
    
    return {
      code: error.code,
      message: error.message,
      httpStatus: errorInfo.httpStatus,
      description: errorInfo.description,
      causes: errorInfo.causes,
      solutions: errorInfo.solutions,
      details: error.details,
      timestamp: error.timestamp,
      requestId: error.requestId
    };
  }

  static isRetryable(error: any): boolean {
    const retryableCodes = [
      'INTERNAL_ERROR',
      'DATABASE_ERROR',
      'EXTERNAL_SERVICE_ERROR',
      'SERVICE_UNAVAILABLE',
      'RATE_LIMIT_EXCEEDED'
    ];
    
    return retryableCodes.includes(error.code);
  }

  static getRetryDelay(error: any, attempt: number): number {
    if (error.code === 'RATE_LIMIT_EXCEEDED') {
      return error.details?.retryAfter * 1000 || 60000;
    }
    
    // Exponential backoff for other errors
    return Math.min(1000 * Math.pow(2, attempt), 30000);
  }
}
```

### 9.3.2 Troubleshooting Guide

Common issues and their solutions.

```markdown
# Troubleshooting Guide

## Authentication Issues

### Problem: "AUTHENTICATION_ERROR" when making requests
**Symptoms:**
- 401 status code
- "Invalid or expired token" message

**Possible Causes:**
1. Token has expired
2. Token is malformed
3. Token signature is invalid
4. Clock skew between client and server

**Solutions:**
1. Check token expiration time
2. Use refresh token to get new access token
3. Verify token format (should be JWT with 3 parts)
4. Ensure system clocks are synchronized

**Code Example:**
```javascript
// Check if token is expired
const token = localStorage.getItem('accessToken');
if (token) {
  const payload = JSON.parse(atob(token.split('.')[1]));
  const now = Date.now() / 1000;
  
  if (payload.exp < now) {
    console.log('Token expired, refreshing...');
    await refreshToken();
  }
}
```

### Problem: "TOKEN_EXPIRED" error
**Symptoms:**
- 401 status code
- Token expiration message

**Solutions:**
1. Implement automatic token refresh
2. Check token expiration before making requests
3. Handle token refresh in API client

**Code Example:**
```javascript
// Automatic token refresh
const apiClient = {
  async request(url, options) {
    let response = await fetch(url, options);
    
    if (response.status === 401) {
      await this.refreshToken();
      // Retry with new token
      response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${this.newToken}`
        }
      });
    }
    
    return response;
  }
};
```

## Authorization Issues

### Problem: "AUTHORIZATION_ERROR" when accessing resources
**Symptoms:**
- 403 status code
- "Insufficient permissions" message

**Possible Causes:**
1. User lacks required permissions
2. Role doesn't have access to resource
3. Tenant-level restrictions

**Solutions:**
1. Check user's assigned roles
2. Verify role permissions
3. Contact tenant administrator

**Code Example:**
```javascript
// Check user permissions
const checkPermission = (user, requiredPermission) => {
  const userPermissions = user.roles.flatMap(role => role.permissions);
  return userPermissions.includes(requiredPermission);
};

if (!checkPermission(user, 'write:users')) {
  console.log('User lacks permission to create users');
}
```

## Validation Issues

### Problem: "VALIDATION_ERROR" on form submission
**Symptoms:**
- 400 status code
- Detailed validation error messages

**Solutions:**
1. Check required fields
2. Validate field formats
3. Ensure field values are within acceptable ranges

**Code Example:**
```javascript
// Client-side validation
const validateUser = (userData) => {
  const errors = [];
  
  if (!userData.email || !/\S+@\S+\.\S+/.test(userData.email)) {
    errors.push({ field: 'email', message: 'Valid email is required' });
  }
  
  if (!userData.password || userData.password.length < 8) {
    errors.push({ field: 'password', message: 'Password must be at least 8 characters' });
  }
  
  return errors;
};
```

## Rate Limiting Issues

### Problem: "RATE_LIMIT_EXCEEDED" error
**Symptoms:**
- 429 status code
- Rate limit headers in response

**Solutions:**
1. Implement exponential backoff
2. Respect rate limit headers
3. Reduce request frequency

**Code Example:**
```javascript
// Exponential backoff retry
const retryWithBackoff = async (operation, maxRetries = 3) => {
  let lastError;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      // Don't retry on authentication or validation errors
      if (error.code === 'RATE_LIMIT_EXCEEDED' && attempt < maxRetries - 1) {
        const delay = error.details?.retryAfter * 1000 || Math.pow(2, attempt) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
};
```

## Network and Connectivity Issues

### Problem: Network timeouts or connection errors
**Symptoms:**
- Request timeouts
- Connection refused errors
- Intermittent failures

**Solutions:**
1. Check network connectivity
2. Verify API endpoint URLs
3. Implement retry logic
4. Check firewall settings

**Code Example:**
```javascript
// Network retry logic
const fetchWithRetry = async (url, options, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, {
        ...options,
        timeout: 10000 // 10 second timeout
      });
      return response;
    } catch (error) {
      if (i === retries - 1) throw error;
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
};
```

## Performance Issues

### Problem: Slow API responses
**Symptoms:**
- High response times
- Timeout errors
- Poor user experience

**Solutions:**
1. Implement caching
2. Use pagination for large datasets
3. Optimize queries
4. Use compression

**Code Example:**
```javascript
// Response caching
const cache = new Map();

const cachedFetch = async (url, options, ttl = 300000) => {
  const cacheKey = `${url}:${JSON.stringify(options)}`;
  const cached = cache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < ttl) {
    return cached.response;
  }
  
  const response = await fetch(url, options);
  cache.set(cacheKey, {
    response: response.clone(),
    timestamp: Date.now()
  });
  
  return response;
};
```

## Data Consistency Issues

### Problem: Stale or inconsistent data
**Symptoms:**
- Data doesn't reflect recent changes
- Conflicting information across requests

**Solutions:**
1. Implement cache invalidation
2. Use optimistic updates carefully
3. Handle concurrent modifications

**Code Example:**
```javascript
// Cache invalidation on updates
const updateUser = async (userId, userData) => {
  try {
    const result = await api.updateUser(userId, userData);
    
    // Invalidate related cache entries
    cache.delete(`user:${userId}`);
    cache.delete('users:list');
    
    return result;
  } catch (error) {
    throw error;
  }
};
```
```

### 9.3.3 Common Issues and Solutions

Frequently encountered problems and their resolutions.

```markdown
# Common Issues and Solutions

## Issue 1: CORS Errors in Browser

**Problem:** Browser blocks requests due to CORS policy

**Error Message:**
```
Access to fetch at 'https://api.gateway.com/v1/users' from origin 'https://myapp.com' 
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present 
on the requested resource.
```

**Solution:**
1. Configure CORS on the server
2. Add your domain to allowed origins
3. For development, use proxy or disable CORS temporarily

**Code Example:**
```javascript
// Development proxy in package.json
{
  "proxy": "http://localhost:8000"
}

// Or use a proxy in webpack config
module.exports = {
  devServer: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  }
};
```

## Issue 2: Token Storage Security

**Problem:** Storing JWT tokens securely in browser

**Security Concerns:**
- XSS attacks can steal tokens from localStorage
- CSRF attacks with cookies
- Token exposure in browser dev tools

**Solutions:**
1. Use httpOnly cookies for refresh tokens
2. Store access tokens in memory when possible
3. Implement proper CSP headers

**Code Example:**
```javascript
// Secure token storage
class SecureTokenStorage {
  constructor() {
    this.accessToken = null; // In memory only
  }

  setTokens(accessToken, refreshToken) {
    this.accessToken = accessToken;
    // Refresh token stored in httpOnly cookie by server
  }

  getAccessToken() {
    return this.accessToken;
  }

  clearTokens() {
    this.accessToken = null;
    // Clear refresh token cookie via API call
    fetch('/api/v1/auth/logout', { method: 'POST' });
  }
}
```

## Issue 3: Handling Concurrent Requests

**Problem:** Multiple requests with expired tokens causing multiple refresh attempts

**Solution:** Implement request queuing during token refresh

**Code Example:**
```javascript
class TokenManager {
  constructor() {
    this.refreshPromise = null;
    this.pendingRequests = [];
  }

  async getValidToken() {
    if (this.isTokenValid()) {
      return this.accessToken;
    }

    if (this.refreshPromise) {
      // Wait for ongoing refresh
      return this.refreshPromise;
    }

    this.refreshPromise = this.refreshToken();
    
    try {
      const newToken = await this.refreshPromise;
      this.refreshPromise = null;
      return newToken;
    } catch (error) {
      this.refreshPromise = null;
      throw error;
    }
  }

  async refreshToken() {
    // Refresh logic here
    const response = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include' // Include httpOnly cookie
    });

    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.token;
      return data.token;
    }

    throw new Error('Token refresh failed');
  }
}
```

## Issue 4: Pagination Performance

**Problem:** Large datasets causing slow loading and poor UX

**Solutions:**
1. Implement virtual scrolling
2. Use cursor-based pagination
3. Add loading states and skeleton screens

**Code Example:**
```javascript
// Infinite scroll with React
const useInfiniteUsers = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [cursor, setCursor] = useState(null);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;

    setLoading(true);
    try {
      const response = await api.getUsers({
        limit: 20,
        cursor: cursor
      });

      setUsers(prev => [...prev, ...response.data]);
      setCursor(response.pagination.nextCursor);
      setHasMore(!!response.pagination.nextCursor);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  }, [cursor, loading, hasMore]);

  return { users, loading, hasMore, loadMore };
};
```

## Issue 5: Error Boundary Implementation

**Problem:** Unhandled errors crashing the application

**Solution:** Implement error boundaries and global error handling

**Code Example:**
```javascript
// React Error Boundary
class ApiErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Log error to monitoring service
    console.error('API Error Boundary caught an error:', error, errorInfo);
    
    // Send to error tracking service
    if (window.Sentry) {
      window.Sentry.captureException(error, {
        contexts: { errorInfo }
      });
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-fallback">
          <h2>Something went wrong</h2>
          <p>We're sorry, but something unexpected happened.</p>
          <button onClick={() => window.location.reload()}>
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// Global error handler
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  
  // Handle API errors specifically
  if (event.reason?.code) {
    const errorInfo = ErrorHandler.getErrorInfo(event.reason.code);
    
    // Show user-friendly message
    showNotification({
      type: 'error',
      title: 'Error',
      message: errorInfo.description,
      actions: errorInfo.solutions
    });
  }
});
```

## Issue 6: Memory Leaks in Long-Running Applications

**Problem:** Memory usage increases over time due to event listeners and timers

**Solutions:**
1. Clean up event listeners
2. Cancel pending requests on component unmount
3. Clear timers and intervals

**Code Example:**
```javascript
// React hook for cleanup
const useApiClient = () => {
  const abortControllerRef = useRef(new AbortController());
  const timersRef = useRef([]);

  const makeRequest = useCallback(async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      signal: abortControllerRef.current.signal
    });
    return response;
  }, []);

  const setTimer = useCallback((callback, delay) => {
    const timerId = setTimeout(callback, delay);
    timersRef.current.push(timerId);
    return timerId;
  }, []);

  useEffect(() => {
    return () => {
      // Cancel all pending requests
      abortControllerRef.current.abort();
      
      // Clear all timers
      timersRef.current.forEach(clearTimeout);
    };
  }, []);

  return { makeRequest, setTimer };
};
```

## Issue 7: Testing API Integration

**Problem:** Difficulty testing API calls in unit tests

**Solutions:**
1. Mock API responses
2. Use test fixtures
3. Implement API client abstraction

**Code Example:**
```javascript
// Jest mock for API client
jest.mock('./api-gateway-sdk', () => ({
  ApiGatewaySDK: jest.fn().mockImplementation(() => ({
    getUsers: jest.fn(),
    createUser: jest.fn(),
    updateUser: jest.fn(),
    deleteUser: jest.fn()
  }))
}));

// Test with mocked responses
describe('UserService', () => {
  let mockSdk;
  let userService;

  beforeEach(() => {
    mockSdk = new ApiGatewaySDK();
    userService = new UserService(mockSdk);
  });

  test('should fetch users successfully', async () => {
    const mockUsers = [
      { id: '1', email: 'user1@example.com' },
      { id: '2', email: 'user2@example.com' }
    ];

    mockSdk.getUsers.mockResolvedValue({
      data: mockUsers,
      pagination: { total: 2 }
    });

    const result = await userService.getUsers();
    
    expect(result.data).toEqual(mockUsers);
    expect(mockSdk.getUsers).toHaveBeenCalledWith({});
  });

  test('should handle API errors', async () => {
    const apiError = new ApiError({
      code: 'VALIDATION_ERROR',
      message: 'Invalid email format'
    });

    mockSdk.createUser.mockRejectedValue(apiError);

    await expect(userService.createUser({
      email: 'invalid-email'
    })).rejects.toThrow('Invalid email format');
  });
});
```

This comprehensive API documentation provides everything needed to successfully integrate with the Multi-Tenant API Gateway, including complete OpenAPI specifications, practical integration examples, and detailed troubleshooting guides.