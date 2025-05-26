# Development Guidelines

## 12.1 Coding Standards

### 12.1.1 JavaScript/TypeScript Guidelines

Comprehensive coding standards for consistent, maintainable code across the Multi-Tenant API Gateway project.

#### TypeScript Configuration

```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": false,
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noImplicitThis": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

#### ESLint Configuration

```json
// .eslintrc.json
{
  "extends": [
    "@typescript-eslint/recommended",
    "@typescript-eslint/recommended-requiring-type-checking",
    "prettier"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "project": "./tsconfig.json"
  },
  "plugins": ["@typescript-eslint", "security", "import"],
  "rules": {
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/explicit-function-return-type": "error",
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/prefer-readonly": "error",
    "@typescript-eslint/prefer-nullish-coalescing": "error",
    "@typescript-eslint/prefer-optional-chain": "error",
    "@typescript-eslint/no-floating-promises": "error",
    "@typescript-eslint/await-thenable": "error",
    "security/detect-object-injection": "error",
    "security/detect-non-literal-regexp": "error",
    "security/detect-unsafe-regex": "error",
    "import/order": [
      "error",
      {
        "groups": [
          "builtin",
          "external",
          "internal",
          "parent",
          "sibling",
          "index"
        ],
        "newlines-between": "always"
      }
    ],
    "prefer-const": "error",
    "no-var": "error",
    "no-console": "warn",
    "eqeqeq": "error",
    "curly": "error"
  }
}
```

#### Prettier Configuration

```json
// .prettierrc
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "bracketSpacing": true,
  "arrowParens": "avoid"
}
```

#### Naming Conventions

```typescript
// File naming: kebab-case
// user-service.ts, auth-middleware.ts, tenant-controller.ts

// Class naming: PascalCase
class UserService {
  // Method naming: camelCase
  async createUser(userData: CreateUserRequest): Promise<User> {
    // Variable naming: camelCase
    const hashedPassword = await this.hashPassword(userData.password);
    
    // Constant naming: SCREAMING_SNAKE_CASE
    const MAX_RETRY_ATTEMPTS = 3;
    
    // Private properties: underscore prefix
    private readonly _database: Db;
    
    return user;
  }
}

// Interface naming: PascalCase with descriptive suffix
interface UserRepository {
  findById(id: string): Promise<User | null>;
}

interface CreateUserRequest {
  email: string;
  password: string;
  profile: UserProfile;
}

// Type naming: PascalCase
type UserRole = 'admin' | 'user' | 'viewer';
type TenantStatus = 'active' | 'suspended' | 'pending';

// Enum naming: PascalCase
enum HttpStatusCode {
  OK = 200,
  CREATED = 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  INTERNAL_SERVER_ERROR = 500,
}
```

#### Function and Method Standards

```typescript
// Function documentation with JSDoc
/**
 * Creates a new user in the specified tenant
 * @param tenantId - The tenant identifier
 * @param userData - User creation data
 * @returns Promise resolving to created user
 * @throws {ValidationError} When user data is invalid
 * @throws {ConflictError} When user email already exists
 */
async function createUser(
  tenantId: string,
  userData: CreateUserRequest
): Promise<User> {
  // Input validation
  if (!tenantId) {
    throw new ValidationError('Tenant ID is required');
  }
  
  if (!userData.email || !isValidEmail(userData.email)) {
    throw new ValidationError('Valid email is required');
  }
  
  // Business logic
  const existingUser = await this.userRepository.findByEmail(
    tenantId,
    userData.email
  );
  
  if (existingUser) {
    throw new ConflictError('User with this email already exists');
  }
  
  // Create user
  const user = await this.userRepository.create(tenantId, {
    ...userData,
    id: generateUserId(),
    createdAt: new Date(),
    status: 'active',
  });
  
  // Audit logging
  this.auditLogger.log('user.created', {
    tenantId,
    userId: user.id,
    email: user.email,
  });
  
  return user;
}

// Error handling patterns
class UserService {
  async updateUser(
    tenantId: string,
    userId: string,
    updates: Partial<User>
  ): Promise<User> {
    try {
      // Validate inputs
      this.validateTenantId(tenantId);
      this.validateUserId(userId);
      this.validateUserUpdates(updates);
      
      // Check permissions
      await this.checkUpdatePermissions(tenantId, userId);
      
      // Perform update
      const updatedUser = await this.userRepository.update(
        tenantId,
        userId,
        updates
      );
      
      if (!updatedUser) {
        throw new NotFoundError('User not found');
      }
      
      return updatedUser;
    } catch (error) {
      // Log error with context
      this.logger.error('Failed to update user', {
        tenantId,
        userId,
        error: error.message,
        stack: error.stack,
      });
      
      // Re-throw with appropriate error type
      if (error instanceof ValidationError || error instanceof NotFoundError) {
        throw error;
      }
      
      throw new InternalServerError('Failed to update user');
    }
  }
}
```

#### Async/Await Patterns

```typescript
// Preferred: async/await over Promises
async function processUserRegistration(userData: CreateUserRequest): Promise<User> {
  // Sequential operations
  const validatedData = await validateUserData(userData);
  const hashedPassword = await hashPassword(validatedData.password);
  const user = await createUserInDatabase({ ...validatedData, hashedPassword });
  await sendWelcomeEmail(user.email);
  
  return user;
}

// Parallel operations when possible
async function getUserWithPermissions(
  tenantId: string,
  userId: string
): Promise<UserWithPermissions> {
  const [user, permissions, roles] = await Promise.all([
    this.userRepository.findById(tenantId, userId),
    this.permissionService.getUserPermissions(tenantId, userId),
    this.roleService.getUserRoles(tenantId, userId),
  ]);
  
  if (!user) {
    throw new NotFoundError('User not found');
  }
  
  return {
    ...user,
    permissions,
    roles,
  };
}

// Error handling in async functions
async function batchProcessUsers(
  tenantId: string,
  userIds: string[]
): Promise<BatchProcessResult> {
  const results: BatchProcessResult = {
    successful: [],
    failed: [],
  };
  
  // Process in batches to avoid overwhelming the system
  const batchSize = 10;
  for (let i = 0; i < userIds.length; i += batchSize) {
    const batch = userIds.slice(i, i + batchSize);
    
    const batchPromises = batch.map(async userId => {
      try {
        const result = await processUser(tenantId, userId);
        results.successful.push(result);
      } catch (error) {
        results.failed.push({
          userId,
          error: error.message,
        });
      }
    });
    
    await Promise.allSettled(batchPromises);
  }
  
  return results;
}
```

### 12.1.2 API Design Principles

RESTful API design standards and conventions.

#### Resource Naming

```typescript
// Resource URLs: plural nouns, kebab-case
GET    /api/v1/tenants
POST   /api/v1/tenants
GET    /api/v1/tenants/{tenantId}
PUT    /api/v1/tenants/{tenantId}
DELETE /api/v1/tenants/{tenantId}

// Nested resources
GET    /api/v1/tenants/{tenantId}/users
POST   /api/v1/tenants/{tenantId}/users
GET    /api/v1/tenants/{tenantId}/users/{userId}
PUT    /api/v1/tenants/{tenantId}/users/{userId}
DELETE /api/v1/tenants/{tenantId}/users/{userId}

// Actions on resources: use verbs in URL path
POST   /api/v1/tenants/{tenantId}/users/{userId}/activate
POST   /api/v1/tenants/{tenantId}/users/{userId}/deactivate
POST   /api/v1/tenants/{tenantId}/users/{userId}/reset-password

// Query parameters for filtering, sorting, pagination
GET /api/v1/users?status=active&role=admin&sort=createdAt&order=desc&page=1&limit=20
```

#### Request/Response Patterns

```typescript
// Standard request wrapper
interface ApiRequest<T = unknown> {
  data: T;
  metadata?: {
    requestId: string;
    timestamp: string;
    version: string;
  };
}

// Standard response wrapper
interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  metadata: {
    requestId: string;
    timestamp: string;
    version: string;
    pagination?: PaginationMetadata;
  };
}

// Pagination metadata
interface PaginationMetadata {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

// Example endpoint implementation
async function getUsers(request: FastifyRequest): Promise<ApiResponse<User[]>> {
  const { tenantId } = request.user;
  const { page = 1, limit = 20, status, role, sort = 'createdAt' } = request.query;
  
  try {
    const result = await userService.list(tenantId, {
      page: Number(page),
      limit: Number(limit),
      filters: { status, role },
      sort,
    });
    
    return {
      success: true,
      data: result.users,
      metadata: {
        requestId: request.id,
        timestamp: new Date().toISOString(),
        version: '1.0',
        pagination: {
          page: result.page,
          limit: result.limit,
          total: result.total,
          totalPages: Math.ceil(result.total / result.limit),
          hasNext: result.page < Math.ceil(result.total / result.limit),
          hasPrevious: result.page > 1,
        },
      },
    };
  } catch (error) {
    throw new ApiError(error.message, error.statusCode || 500);
  }
}
```

#### HTTP Status Codes

```typescript
// Standard HTTP status code usage
enum HttpStatusCode {
  // Success
  OK = 200,                    // GET, PUT successful
  CREATED = 201,               // POST successful
  NO_CONTENT = 204,            // DELETE successful
  
  // Client Errors
  BAD_REQUEST = 400,           // Invalid request data
  UNAUTHORIZED = 401,          // Authentication required
  FORBIDDEN = 403,             // Insufficient permissions
  NOT_FOUND = 404,             // Resource not found
  CONFLICT = 409,              // Resource conflict (duplicate)
  UNPROCESSABLE_ENTITY = 422,  // Validation errors
  TOO_MANY_REQUESTS = 429,     // Rate limit exceeded
  
  // Server Errors
  INTERNAL_SERVER_ERROR = 500, // Unexpected server error
  BAD_GATEWAY = 502,           // External service error
  SERVICE_UNAVAILABLE = 503,   // Service temporarily unavailable
}

// Error response examples
const errorResponses = {
  validation: {
    success: false,
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Request validation failed',
      details: {
        fields: {
          email: 'Invalid email format',
          password: 'Password must be at least 8 characters',
        },
      },
    },
    metadata: {
      requestId: 'req_123',
      timestamp: '2024-01-01T00:00:00Z',
      version: '1.0',
    },
  },
  
  notFound: {
    success: false,
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'User not found',
    },
    metadata: {
      requestId: 'req_124',
      timestamp: '2024-01-01T00:00:00Z',
      version: '1.0',
    },
  },
  
  rateLimit: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please try again later.',
      details: {
        retryAfter: 60,
        limit: 100,
        remaining: 0,
      },
    },
    metadata: {
      requestId: 'req_125',
      timestamp: '2024-01-01T00:00:00Z',
      version: '1.0',
    },
  },
};
```

### 12.1.3 Database Design Patterns

MongoDB schema design and query patterns for multi-tenant architecture.

#### Collection Schema Design

```typescript
// Tenant collection schema
interface TenantDocument {
  _id: ObjectId;
  tenantId: string;           // Unique tenant identifier
  name: string;               // Display name
  domain?: string;            // Optional custom domain
  status: 'active' | 'suspended' | 'pending';
  settings: {
    maxUsers: number;
    features: string[];
    billing: {
      plan: string;
      maxApiCalls: number;
      billingEmail: string;
    };
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

// User collection schema with tenant isolation
interface UserDocument {
  _id: ObjectId;
  tenantId: string;           // Tenant isolation field
  userId: string;             // Unique within tenant
  email: string;              // Unique within tenant
  cognitoUserId: string;      // AWS Cognito user ID
  profile: {
    firstName: string;
    lastName: string;
    avatar?: string;
    timezone?: string;
    locale?: string;
  };
  roles: string[];            // Array of role names
  status: 'active' | 'inactive' | 'pending';
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

// Role collection schema
interface RoleDocument {
  _id: ObjectId;
  tenantId: string;           // Tenant isolation
  name: string;               // Unique within tenant
  description: string;
  permissions: string[];      // Array of permission strings
  isSystem: boolean;          // System vs custom role
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

// Audit log collection schema
interface AuditLogDocument {
  _id: ObjectId;
  tenantId: string;           // Tenant isolation
  action: string;             // Action performed
  resource: string;           // Resource affected
  resourceId: string;         // ID of affected resource
  userId: string;             // User who performed action
  timestamp: Date;
  details: Record<string, unknown>; // Additional context
  ipAddress: string;
  userAgent: string;
}
```

#### Index Strategies

```typescript
// Database indexes for optimal query performance
const indexDefinitions = {
  tenants: [
    { key: { tenantId: 1 }, unique: true },
    { key: { domain: 1 }, unique: true, sparse: true },
    { key: { status: 1 } },
    { key: { createdAt: 1 } },
  ],
  
  users: [
    { key: { tenantId: 1, email: 1 }, unique: true },
    { key: { tenantId: 1, userId: 1 }, unique: true },
    { key: { cognitoUserId: 1 }, unique: true },
    { key: { tenantId: 1, status: 1 } },
    { key: { tenantId: 1, roles: 1 } },
    { key: { tenantId: 1, createdAt: 1 } },
    { key: { tenantId: 1, lastLoginAt: 1 } },
  ],
  
  roles: [
    { key: { tenantId: 1, name: 1 }, unique: true },
    { key: { tenantId: 1, isSystem: 1 } },
  ],
  
  auditLogs: [
    { key: { tenantId: 1, timestamp: -1 } },
    { key: { tenantId: 1, userId: 1, timestamp: -1 } },
    { key: { tenantId: 1, action: 1, timestamp: -1 } },
    { key: { tenantId: 1, resource: 1, resourceId: 1 } },
    // TTL index for automatic cleanup
    { key: { timestamp: 1 }, expireAfterSeconds: 31536000 }, // 1 year
  ],
};
```

#### Query Patterns

```typescript
// Repository pattern for tenant-aware queries
class UserRepository {
  constructor(private readonly db: Db) {}
  
  // Always include tenantId in queries for data isolation
  async findById(tenantId: string, userId: string): Promise<UserDocument | null> {
    return this.db.collection<UserDocument>('users').findOne({
      tenantId,
      userId,
    });
  }
  
  async findByEmail(tenantId: string, email: string): Promise<UserDocument | null> {
    return this.db.collection<UserDocument>('users').findOne({
      tenantId,
      email: email.toLowerCase(),
    });
  }
  
  async list(
    tenantId: string,
    options: {
      page: number;
      limit: number;
      filters?: Partial<Pick<UserDocument, 'status' | 'roles'>>;
      sort?: string;
    }
  ): Promise<{ users: UserDocument[]; total: number }> {
    const { page, limit, filters = {}, sort = 'createdAt' } = options;
    
    // Build query with tenant isolation
    const query: FilterQuery<UserDocument> = { tenantId };
    
    // Add filters
    if (filters.status) {
      query.status = filters.status;
    }
    
    if (filters.roles && filters.roles.length > 0) {
      query.roles = { $in: filters.roles };
    }
    
    // Execute query with pagination
    const [users, total] = await Promise.all([
      this.db
        .collection<UserDocument>('users')
        .find(query)
        .sort({ [sort]: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray(),
      this.db.collection<UserDocument>('users').countDocuments(query),
    ]);
    
    return { users, total };
  }
  
  async create(tenantId: string, userData: Omit<UserDocument, '_id' | 'tenantId'>): Promise<UserDocument> {
    const user: Omit<UserDocument, '_id'> = {
      ...userData,
      tenantId, // Always set tenant isolation
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    const result = await this.db.collection<UserDocument>('users').insertOne(user);
    
    return {
      ...user,
      _id: result.insertedId,
    };
  }
  
  async update(
    tenantId: string,
    userId: string,
    updates: Partial<UserDocument>
  ): Promise<UserDocument | null> {
    // Remove fields that shouldn't be updated
    const { _id, tenantId: _, userId: __, createdAt, ...allowedUpdates } = updates;
    
    const result = await this.db.collection<UserDocument>('users').findOneAndUpdate(
      { tenantId, userId },
      {
        $set: {
          ...allowedUpdates,
          updatedAt: new Date(),
        },
      },
      { returnDocument: 'after' }
    );
    
    return result.value;
  }
  
  async delete(tenantId: string, userId: string): Promise<boolean> {
    const result = await this.db.collection<UserDocument>('users').deleteOne({
      tenantId,
      userId,
    });
    
    return result.deletedCount === 1;
  }
}
```

## 12.2 Security Best Practices

### 12.2.1 Secure Coding Guidelines

Security-first development practices for the API Gateway.

#### Input Validation and Sanitization

```typescript
// Input validation using Joi schemas
import Joi from 'joi';
import DOMPurify from 'isomorphic-dompurify';

// Validation schemas
const schemas = {
  email: Joi.string().email().lowercase().max(255).required(),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    }),
  tenantId: Joi.string().pattern(/^tenant_\d+_[a-z0-9]+$/).required(),
  userId: Joi.string().uuid().required(),
  name: Joi.string().min(1).max(100).pattern(/^[a-zA-Z0-9\s\-_]+$/).required(),
};

// Input sanitization middleware
function sanitizeInput(input: unknown): unknown {
  if (typeof input === 'string') {
    // Remove HTML tags and encode special characters
    return DOMPurify.sanitize(input, { ALLOWED_TAGS: [] });
  }
  
  if (Array.isArray(input)) {
    return input.map(sanitizeInput);
  }
  
  if (input && typeof input === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      sanitized[key] = sanitizeInput(value);
    }
    return sanitized;
  }
  
  return input;
}

// Validation middleware
function validateRequest<T>(schema: Joi.ObjectSchema<T>) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      // Sanitize input first
      const sanitizedBody = sanitizeInput(request.body);
      
      // Validate against schema
      const { error, value } = schema.validate(sanitizedBody, {
        abortEarly: false,
        stripUnknown: true,
      });
      
      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
        }));
        
        return reply.code(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request validation failed',
            details: { fields: validationErrors },
          },
        });
      }
      
      // Replace request body with validated and sanitized data
      request.body = value;
    } catch (error) {
      request.log.error('Validation error:', error);
      return reply.code(500).send({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
        },
      });
    }
  };
}

// Usage example
const createUserSchema = Joi.object({
  email: schemas.email,
  password: schemas.password,
  profile: Joi.object({
    firstName: schemas.name,
    lastName: schemas.name,
    avatar: Joi.string().uri().optional(),
  }).required(),
  roles: Joi.array().items(Joi.string().valid('admin', 'user', 'viewer')).min(1).required(),
});

// Route with validation
fastify.post('/users', {
  preHandler: [authMiddleware, validateRequest(createUserSchema)],
  handler: createUserHandler,
});
```

#### SQL/NoSQL Injection Prevention

```typescript
// Safe query building for MongoDB
class SecureQueryBuilder {
  // Prevent NoSQL injection by validating query operators
  private static readonly ALLOWED_OPERATORS = [
    '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
    '$in', '$nin', '$exists', '$type', '$regex'
  ];
  
  static sanitizeQuery(query: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(query)) {
      // Prevent injection through field names
      if (key.startsWith('$') && !this.ALLOWED_OPERATORS.includes(key)) {
        continue; // Skip dangerous operators
      }
      
      // Sanitize values
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        sanitized[key] = this.sanitizeQuery(value as Record<string, unknown>);
      } else if (typeof value === 'string') {
        // Escape special regex characters if using $regex
        sanitized[key] = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  // Safe query methods
  static buildUserQuery(
    tenantId: string,
    filters: {
      status?: string;
      role?: string;
      email?: string;
    }
  ): FilterQuery<UserDocument> {
    const query: FilterQuery<UserDocument> = { tenantId };
    
    if (filters.status && ['active', 'inactive', 'pending'].includes(filters.status)) {
      query.status = filters.status as UserDocument['status'];
    }
    
    if (filters.role && ['admin', 'user', 'viewer'].includes(filters.role)) {
      query.roles = { $in: [filters.role] };
    }
    
    if (filters.email) {
      // Use exact match for email, not regex
      query.email = filters.email.toLowerCase();
    }
    
    return query;
  }
}

// Usage in repository
async findUsers(
  tenantId: string,
  filters: UserFilters
): Promise<UserDocument[]> {
  const safeQuery = SecureQueryBuilder.buildUserQuery(tenantId, filters);
  
  return this.db
    .collection<UserDocument>('users')
    .find(safeQuery)
    .toArray();
}
```

#### Authentication and Authorization Security

```typescript
// Secure JWT handling
class JWTSecurityService {
  private readonly secretKey: string;
  private readonly issuer: string;
  private readonly audience: string;
  
  constructor(config: JWTConfig) {
    this.secretKey = config.secretKey;
    this.issuer = config.issuer;
    this.audience = config.audience;
  }
  
  // Generate secure JWT with proper claims
  generateToken(payload: TokenPayload): string {
    const now = Math.floor(Date.now() / 1000);
    
    const claims = {
      ...payload,
      iss: this.issuer,
      aud: this.audience,
      iat: now,
      exp: now + (15 * 60), // 15 minutes
      nbf: now,
      jti: crypto.randomUUID(), // Unique token ID
    };
    
    return jwt.sign(claims, this.secretKey, {
      algorithm: 'HS256',
    });
  }
  
  // Secure token validation
  async validateToken(token: string): Promise<TokenValidationResult> {
    try {
      const decoded = jwt.verify(token, this.secretKey, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['HS256'],
      }) as JWTPayload;
      
      // Additional security checks
      if (!decoded.sub || !decoded.tenantId) {
        throw new Error('Invalid token claims');
      }
      
      // Check if token is blacklisted
      const isBlacklisted = await this.isTokenBlacklisted(decoded.jti);
      if (isBlacklisted) {
        throw new Error('Token has been revoked');
      }
      
      return {
        valid: true,
        payload: decoded,
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message,
      };
    }
  }
  
  // Token blacklisting for logout/revocation
  async blacklistToken(tokenId: string, expiresAt: Date): Promise<void> {
    await this.redis.setex(
      `blacklist:${tokenId}`,
      Math.floor((expiresAt.getTime() - Date.now()) / 1000),
      'revoked'
    );
  }
  
  private async isTokenBlacklisted(tokenId: string): Promise<boolean> {
    const result = await this.redis.get(`blacklist:${tokenId}`);
    return result === 'revoked';
  }
}

// Secure password handling
class PasswordSecurityService {
  private static readonly SALT_ROUNDS = 12;
  private static readonly PEPPER = process.env.PASSWORD_PEPPER || '';
  
  // Hash password with salt and pepper
  static async hashPassword(password: string): Promise<string> {
    const pepperedPassword = password + this.PEPPER;
    return bcrypt.hash(pepperedPassword, this.SALT_ROUNDS);
  }
  
  // Verify password
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    const pepperedPassword = password + this.PEPPER;
    return bcrypt.compare(pepperedPassword, hash);
  }
  
  // Generate secure random password
  static generateSecurePassword(length: number = 16): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length);
      password += charset[randomIndex];
    }
    
    return password;
  }
  
  // Check password strength
  static checkPasswordStrength(password: string): PasswordStrengthResult {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),
      symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      noCommonPatterns: !this.hasCommonPatterns(password),
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    
    return {
      score,
      maxScore: Object.keys(checks).length,
      strength: this.getStrengthLevel(score),
      checks,
    };
  }
  
  private static hasCommonPatterns(password: string): boolean {
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /admin/i,
      /(.)\1{2,}/, // Repeated characters
    ];
    
    return commonPatterns.some(pattern => pattern.test(password));
  }
  
  private static getStrengthLevel(score: number): 'weak' | 'fair' | 'good' | 'strong' {
    if (score < 3) return 'weak';
    if (score < 4) return 'fair';
    if (score < 5) return 'good';
    return 'strong';
  }
}
```

### 12.2.2 Data Protection Standards

Comprehensive data protection and privacy measures.

#### Data Encryption

```typescript
// Encryption service for sensitive data
class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyDerivationIterations = 100000;
  
  constructor(private readonly masterKey: string) {}
  
  // Encrypt sensitive data
  encrypt(data: string, additionalData?: string): EncryptedData {
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Derive key from master key and salt
    const key = crypto.pbkdf2Sync(
      this.masterKey,
      salt,
      this.keyDerivationIterations,
      32,
      'sha256'
    );
    
    const cipher = crypto.createCipher(this.algorithm, key);
    cipher.setAAD(Buffer.from(additionalData || '', 'utf8'));
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: this.algorithm,
    };
  }
  
  // Decrypt sensitive data
  decrypt(encryptedData: EncryptedData, additionalData?: string): string {
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    // Derive the same key
    const key = crypto.pbkdf2Sync(
      this.masterKey,
      salt,
      this.keyDerivationIterations,
      32,
      'sha256'
    );
    
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAuthTag(authTag);
    decipher.setAAD(Buffer.from(additionalData || '', 'utf8'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  // Hash sensitive data for searching
  hashForSearch(data: string): string {
    return crypto
      .createHmac('sha256', this.masterKey)
      .update(data.toLowerCase())
      .digest('hex');
  }
}

// PII (Personally Identifiable Information) handling
class PIIProtectionService {
  constructor(private readonly encryptionService: EncryptionService) {}
  
  // Encrypt PII fields before storing
  encryptPII(user: UserDocument): UserDocument {
    const encrypted = { ...user };
    
    // Encrypt sensitive fields
    if (user.profile.firstName) {
      encrypted.profile.firstName = this.encryptionService.encrypt(
        user.profile.firstName,
        user.tenantId
      ).encrypted;
    }
    
    if (user.profile.lastName) {
      encrypted.profile.lastName = this.encryptionService.encrypt(
        user.profile.lastName,
        user.tenantId
      ).encrypted;
    }
    
    // Create searchable hash for email
    encrypted.emailHash = this.encryptionService.hashForSearch(user.email);
    
    return encrypted;
  }
  
  // Decrypt PII fields when retrieving
  decryptPII(encryptedUser: UserDocument): UserDocument {
    const decrypted = { ...encryptedUser };
    
    try {
      if (encryptedUser.profile.firstName) {
        decrypted.profile.firstName = this.encryptionService.decrypt(
          encryptedUser.profile.firstName as any,
          encryptedUser.tenantId
        );
      }
      
      if (encryptedUser.profile.lastName) {
        decrypted.profile.lastName = this.encryptionService.decrypt(
          encryptedUser.profile.lastName as any,
          encryptedUser.tenantId
        );
      }
    } catch (error) {
      // Log decryption failure but don't expose error details
      console.error('PII decryption failed for user:', encryptedUser.userId);
      throw new Error('Data access error');
    }
    
    return decrypted;
  }
  
  // Anonymize user data for analytics
  anonymizeUser(user: UserDocument): AnonymizedUser {
    return {
      id: crypto.createHash('sha256').update(user.userId).digest('hex'),
      tenantId: crypto.createHash('sha256').update(user.tenantId).digest('hex'),
      roles: user.roles,
      status: user.status,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
      // Remove all PII
    };
  }
}
```

#### Data Retention and Deletion

```typescript
// Data retention policy implementation
class DataRetentionService {
  constructor(
    private readonly db: Db,
    private readonly auditLogger: AuditLogger
  ) {}
  
  // Implement right to be forgotten (GDPR Article 17)
  async deleteUserData(tenantId: string, userId: string): Promise<void> {
    const session = this.db.client.startSession();
    
    try {
      await session.withTransaction(async () => {
        // 1. Delete user record
        await this.db.collection('users').deleteOne(
          { tenantId, userId },
          { session }
        );
        
        // 2. Anonymize audit logs (keep for compliance)
        await this.db.collection('auditLogs').updateMany(
          { tenantId, userId },
          {
            $set: {
              userId: 'DELETED_USER',
              'details.email': 'REDACTED',
              'details.name': 'REDACTED',
            },
          },
          { session }
        );
        
        // 3. Delete user sessions
        await this.db.collection('sessions').deleteMany(
          { tenantId, userId },
          { session }
        );
        
        // 4. Delete API keys
        await this.db.collection('apiKeys').deleteMany(
          { tenantId, createdBy: userId },
          { session }
        );
        
        // 5. Log deletion for compliance
        await this.auditLogger.log('user.data_deleted', {
          tenantId,
          userId,
          deletedAt: new Date(),
          reason: 'user_request',
        });
      });
    } finally {
      await session.endSession();
    }
  }
  
  // Automatic data cleanup based on retention policies
  async cleanupExpiredData(): Promise<void> {
    const now = new Date();
    
    // Clean up expired sessions (30 days)
    const sessionCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    await this.db.collection('sessions').deleteMany({
      lastAccessedAt: { $lt: sessionCutoff },
    });
    
    // Clean up old audit logs (7 years for compliance)
    const auditCutoff = new Date(now.getTime() - 7 * 365 * 24 * 60 * 60 * 1000);
    await this.db.collection('auditLogs').deleteMany({
      timestamp: { $lt: auditCutoff },
    });
    
    // Clean up inactive tenants (marked for deletion)
    await this.cleanupDeletedTenants();
  }
  
  private async cleanupDeletedTenants(): Promise<void> {
    const deletionCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days
    
    const tenantsToDelete = await this.db.collection('tenants').find({
      status: 'deleted',
      deletedAt: { $lt: deletionCutoff },
    }).toArray();
    
    for (const tenant of tenantsToDelete) {
      await this.permanentlyDeleteTenant(tenant.tenantId);
    }
  }
  
  private async permanentlyDeleteTenant(tenantId: string): Promise<void> {
    const session = this.db.client.startSession();
    
    try {
      await session.withTransaction(async () => {
        // Delete all tenant data
        const collections = ['users', 'roles', 'auditLogs', 'sessions', 'apiKeys'];
        
        for (const collectionName of collections) {
          await this.db.collection(collectionName).deleteMany(
            { tenantId },
            { session }
          );
        }
        
        // Finally delete tenant record
        await this.db.collection('tenants').deleteOne(
          { tenantId },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }
  }
}
```

### 12.2.3 Vulnerability Management

Proactive security vulnerability identification and remediation.

#### Dependency Security

```typescript
// Automated dependency vulnerability scanning
class DependencySecurityService {
  // Check for known vulnerabilities in dependencies
  async scanDependencies(): Promise<VulnerabilityReport> {
    const packageJson = require('../../package.json');
    const dependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    };
    
    const vulnerabilities: Vulnerability[] = [];
    
    for (const [packageName, version] of Object.entries(dependencies)) {
      const vulns = await this.checkPackageVulnerabilities(packageName, version as string);
      vulnerabilities.push(...vulns);
    }
    
    return {
      scannedAt: new Date(),
      totalPackages: Object.keys(dependencies).length,
      vulnerabilities,
      summary: this.summarizeVulnerabilities(vulnerabilities),
    };
  }
  
  private async checkPackageVulnerabilities(
    packageName: string,
    version: string
  ): Promise<Vulnerability[]> {
    // Integration with vulnerability databases (npm audit, Snyk, etc.)
    try {
      const response = await fetch(`https://registry.npmjs.org/-/npm/v1/security/audits`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: packageName,
          version,
        }),
      });
      
      const data = await response.json();
      return this.parseVulnerabilityData(data);
    } catch (error) {
      console.error(`Failed to check vulnerabilities for ${packageName}:`, error);
      return [];
    }
  }
  
  private summarizeVulnerabilities(vulnerabilities: Vulnerability[]): VulnerabilitySummary {
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    
    vulnerabilities.forEach(vuln => {
      summary[vuln.severity]++;
    });
    
    return summary;
  }
}

// Security headers middleware
function securityHeadersMiddleware() {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    // Prevent XSS attacks
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('X-XSS-Protection', '1; mode=block');
    
    // HTTPS enforcement
    reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    
    // Content Security Policy
    reply.header('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "media-src 'self'",
      "frame-src 'none'",
    ].join('; '));
    
    // Referrer Policy
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions Policy
    reply.header('Permissions-Policy', [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
    ].join(', '));
    
    // Remove server information
    reply.removeHeader('X-Powered-By');
    reply.removeHeader('Server');
  };
}
```

## 12.3 Code Review Process

### 12.3.1 Review Checklist

Comprehensive code review guidelines and checklists.

#### Security Review Checklist

```markdown
## Security Review Checklist

### Authentication & Authorization
- [ ] All endpoints require proper authentication
- [ ] Authorization checks are performed before data access
- [ ] JWT tokens are properly validated
- [ ] Session management is secure
- [ ] Password handling follows security standards

### Input Validation
- [ ] All user inputs are validated and sanitized
- [ ] SQL/NoSQL injection prevention measures are in place
- [ ] XSS prevention is implemented
- [ ] File upload security is properly handled
- [ ] Request size limits are enforced

### Data Protection
- [ ] Sensitive data is encrypted at rest and in transit
- [ ] PII is properly protected
- [ ] Data access is logged for audit purposes
- [ ] Tenant isolation is maintained
- [ ] No sensitive data in logs or error messages

### Error Handling
- [ ] Errors don't expose sensitive information
- [ ] Proper error logging is implemented
- [ ] Graceful degradation is handled
- [ ] Rate limiting is in place
- [ ] Circuit breakers are implemented where needed

### Dependencies
- [ ] No known vulnerable dependencies
- [ ] Dependencies are up to date
- [ ] Minimal dependency footprint
- [ ] License compatibility checked
```

#### Performance Review Checklist

```markdown
## Performance Review Checklist

### Database Operations
- [ ] Queries are optimized with proper indexes
- [ ] N+1 query problems are avoided
- [ ] Connection pooling is used
- [ ] Transactions are used appropriately
- [ ] Bulk operations are used for large datasets

### Caching
- [ ] Appropriate caching strategies are implemented
- [ ] Cache invalidation is handled correctly
- [ ] Cache keys are properly namespaced
- [ ] Memory usage is optimized
- [ ] Cache hit rates are monitored

### API Design
- [ ] Pagination is implemented for list endpoints
- [ ] Response sizes are reasonable
- [ ] Unnecessary data is not returned
- [ ] Compression is used where appropriate
- [ ] HTTP caching headers are set correctly

### Resource Management
- [ ] Memory leaks are prevented
- [ ] File handles are properly closed
- [ ] Background jobs are optimized
- [ ] Resource cleanup is implemented
- [ ] Monitoring and alerting are in place
```

### 12.3.2 Security Review Guidelines

Detailed security review process and standards.

#### Code Review Security Standards

```typescript
// Security-focused code review examples

// ❌ BAD: Vulnerable to injection attacks
async function getUserByEmail(email: string): Promise<User> {
  const query = `db.users.findOne({email: "${email}"})`;
  return eval(query); // Never use eval!
}

// ✅ GOOD: Safe parameterized query
async function getUserByEmail(tenantId: string, email: string): Promise<User | null> {
  return this.db.collection<User>('users').findOne({
    tenantId, // Always include tenant isolation
    email: email.toLowerCase(), // Normalize input
  });
}

// ❌ BAD: Exposes sensitive information
async function loginUser(email: string, password: string): Promise<LoginResult> {
  const user = await this.getUserByEmail(email);
  if (!user) {
    throw new Error(`User with email ${email} not found`); // Exposes user existence
  }
  
  if (user.password !== password) { // Plain text comparison!
    throw new Error('Invalid password');
  }
  
  return { user, token: this.generateToken(user) };
}

// ✅ GOOD: Secure authentication
async function loginUser(email: string, password: string): Promise<LoginResult> {
  // Rate limiting should be applied at middleware level
  
  const user = await this.getUserByEmail(email);
  
  // Use constant-time comparison to prevent timing attacks
  const isValidUser = user !== null;
  const isValidPassword = user ? 
    await this.passwordService.verify(password, user.passwordHash) : 
    await this.passwordService.verify(password, 'dummy_hash'); // Prevent timing attacks
  
  if (!isValidUser || !isValidPassword) {
    // Generic error message
    throw new AuthenticationError('Invalid credentials');
  }
  
  // Log successful login
  await this.auditLogger.log('user.login', {
    userId: user.id,
    tenantId: user.tenantId,
    ipAddress: this.getClientIP(),
  });
  
  return {
    user: this.sanitizeUserForResponse(user),
    token: this.generateToken(user),
  };
}

// ❌ BAD: Missing authorization checks
async function updateUser(userId: string, updates: Partial<User>): Promise<User> {
  return this.userRepository.update(userId, updates);
}

// ✅ GOOD: Proper authorization
async function updateUser(
  requestingUserId: string,
  tenantId: string,
  targetUserId: string,
  updates: Partial<User>
): Promise<User> {
  // Check if user can update the target user
  const canUpdate = await this.authorizationService.canUpdateUser(
    requestingUserId,
    tenantId,
    targetUserId
  );
  
  if (!canUpdate) {
    throw new ForbiddenError('Insufficient permissions to update user');
  }
  
  // Validate updates don't include forbidden fields
  const allowedFields = ['profile', 'preferences'];
  const sanitizedUpdates = this.sanitizeUpdates(updates, allowedFields);
  
  // Perform update with audit logging
  const updatedUser = await this.userRepository.update(
    tenantId,
    targetUserId,
    sanitizedUpdates
  );
  
  await this.auditLogger.log('user.updated', {
    updatedBy: requestingUserId,
    targetUser: targetUserId,
    tenantId,
    changes: Object.keys(sanitizedUpdates),
  });
  
  return updatedUser;
}
```

### 12.3.3 Performance Review Criteria

Performance optimization guidelines and review criteria.

#### Performance Optimization Patterns

```typescript
// Performance-focused code review examples

// ❌ BAD: N+1 query problem
async function getUsersWithRoles(tenantId: string): Promise<UserWithRoles[]> {
  const users = await this.userRepository.findByTenant(tenantId);
  
  const usersWithRoles = [];
  for (const user of users) {
    const roles = await this.roleRepository.findByUserId(tenantId, user.id); // N+1!
    usersWithRoles.push({ ...user, roles });
  }
  
  return usersWithRoles;
}

// ✅ GOOD: Optimized with single query
async function getUsersWithRoles(tenantId: string): Promise<UserWithRoles[]> {
  // Use aggregation to join data in single query
  return this.db.collection('users').aggregate([
    { $match: { tenantId } },
    {
      $lookup: {
        from: 'userRoles',
        localField: 'id',
        foreignField: 'userId',
        as: 'userRoles',
      },
    },
    {
      $lookup: {
        from: 'roles',
        localField: 'userRoles.roleId',
        foreignField: 'id',
        as: 'roles',
      },
    },
    {
      $project: {
        id: 1,
        email: 1,
        profile: 1,
        roles: { $map: { input: '$roles', as: 'role', in: '$$role.name' } },
      },
    },
  ]).toArray();
}

// ❌ BAD: Inefficient caching
class UserService {
  async getUser(tenantId: string, userId: string): Promise<User> {
    // Cache key doesn't include tenant - security issue!
    const cacheKey = `user:${userId}`;
    
    let user = await this.cache.get(cacheKey);
    if (!user) {
      user = await this.userRepository.findById(tenantId, userId);
      await this.cache.set(cacheKey, user, 3600); // 1 hour
    }
    
    return user;
  }
}

// ✅ GOOD: Efficient and secure caching
class UserService {
  async getUser(tenantId: string, userId: string): Promise<User> {
    // Include tenant in cache key for security
    const cacheKey = `user:${tenantId}:${userId}`;
    
    let user = await this.cache.get(cacheKey);
    if (!user) {
      user = await this.userRepository.findById(tenantId, userId);
      if (user) {
        // Cache with appropriate TTL
        await this.cache.set(cacheKey, user, 900); // 15 minutes
      }
    }
    
    return user;
  }
  
  async updateUser(
    tenantId: string,
    userId: string,
    updates: Partial<User>
  ): Promise<User> {
    const updatedUser = await this.userRepository.update(tenantId, userId, updates);
    
    // Invalidate cache after update
    const cacheKey = `user:${tenantId}:${userId}`;
    await this.cache.del(cacheKey);
    
    return updatedUser;
  }
}

// ❌ BAD: Memory inefficient
async function processLargeDataset(tenantId: string): Promise<ProcessingResult> {
  // Loads all data into memory at once
  const allUsers = await this.userRepository.findAll(tenantId);
  
  const results = [];
  for (const user of allUsers) {
    const processed = await this.processUser(user);
    results.push(processed);
  }
  
  return { results };
}

// ✅ GOOD: Memory efficient streaming
async function processLargeDataset(tenantId: string): Promise<ProcessingResult> {
  const batchSize = 100;
  let offset = 0;
  let totalProcessed = 0;
  const errors: ProcessingError[] = [];
  
  while (true) {
    // Process in batches
    const batch = await this.userRepository.findBatch(tenantId, offset, batchSize);
    
    if (batch.length === 0) {
      break; // No more data
    }
    
    // Process batch in parallel
    const batchPromises = batch.map(async user => {
      try {
        await this.processUser(user);
        totalProcessed++;
      } catch (error) {
        errors.push({
          userId: user.id,
          error: error.message,
        });
      }
    });
    
    await Promise.allSettled(batchPromises);
    
    offset += batchSize;
    
    // Optional: Add delay to prevent overwhelming the system
    if (batch.length === batchSize) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  
  return {
    totalProcessed,
    errors,
  };
}
```

This comprehensive development guidelines documentation provides the foundation for maintaining high code quality, security, and performance standards throughout the Multi-Tenant API Gateway project development lifecycle. 