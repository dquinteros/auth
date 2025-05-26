# Testing Strategy

## 11.1 Unit Testing

### 11.1.1 Authentication Tests

Comprehensive unit tests for authentication components and middleware.

```typescript
// tests/unit/auth/jwtValidation.test.ts
import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { JWTValidationService } from '../../../src/services/jwtValidationService';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

// Mock AWS JWT Verifier
jest.mock('aws-jwt-verify');

describe('JWT Validation Service', () => {
  let jwtService: JWTValidationService;
  let mockVerifier: jest.Mocked<CognitoJwtVerifier>;

  beforeEach(() => {
    mockVerifier = {
      verify: jest.fn()
    } as any;
    
    (CognitoJwtVerifier.create as jest.Mock).mockReturnValue(mockVerifier);
    
    jwtService = new JWTValidationService({
      userPoolId: 'us-east-1_TEST123',
      clientId: 'test-client-id',
      region: 'us-east-1'
    });
  });

  describe('validateToken', () => {
    it('should validate a valid JWT token', async () => {
      const mockPayload = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
        'custom:roles': '["admin", "user"]',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      mockVerifier.verify.mockResolvedValue(mockPayload);

      const result = await jwtService.validateToken('valid.jwt.token');

      expect(result).toEqual({
        valid: true,
        payload: mockPayload,
        user: {
          id: 'user-123',
          email: 'test@example.com',
          tenantId: 'tenant-123',
          roles: ['admin', 'user']
        }
      });
    });

    it('should reject an expired token', async () => {
      mockVerifier.verify.mockRejectedValue(new Error('Token expired'));

      const result = await jwtService.validateToken('expired.jwt.token');

      expect(result).toEqual({
        valid: false,
        error: 'Token expired'
      });
    });

    it('should reject a token with invalid signature', async () => {
      mockVerifier.verify.mockRejectedValue(new Error('Invalid signature'));

      const result = await jwtService.validateToken('invalid.jwt.token');

      expect(result).toEqual({
        valid: false,
        error: 'Invalid signature'
      });
    });

    it('should handle malformed custom claims', async () => {
      const mockPayload = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
        'custom:roles': 'invalid-json',
        exp: Math.floor(Date.now() / 1000) + 3600
      };

      mockVerifier.verify.mockResolvedValue(mockPayload);

      const result = await jwtService.validateToken('malformed.jwt.token');

      expect(result.valid).toBe(true);
      expect(result.user?.roles).toEqual([]);
    });
  });

  describe('extractTenantId', () => {
    it('should extract tenant ID from valid token', async () => {
      const mockPayload = {
        'custom:tenantId': 'tenant-456'
      };

      mockVerifier.verify.mockResolvedValue(mockPayload);

      const tenantId = await jwtService.extractTenantId('valid.jwt.token');
      expect(tenantId).toBe('tenant-456');
    });

    it('should return null for token without tenant ID', async () => {
      const mockPayload = {
        sub: 'user-123'
      };

      mockVerifier.verify.mockResolvedValue(mockPayload);

      const tenantId = await jwtService.extractTenantId('no-tenant.jwt.token');
      expect(tenantId).toBeNull();
    });
  });
});
```

```typescript
// tests/unit/auth/authMiddleware.test.ts
import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { FastifyRequest, FastifyReply } from 'fastify';
import { authMiddleware } from '../../../src/middleware/authMiddleware';
import { JWTValidationService } from '../../../src/services/jwtValidationService';

jest.mock('../../../src/services/jwtValidationService');

describe('Auth Middleware', () => {
  let mockRequest: Partial<FastifyRequest>;
  let mockReply: Partial<FastifyReply>;
  let mockJWTService: jest.Mocked<JWTValidationService>;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      log: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn()
      } as any
    };

    mockReply = {
      code: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis()
    };

    mockJWTService = {
      validateToken: jest.fn()
    } as any;

    (JWTValidationService as jest.Mock).mockImplementation(() => mockJWTService);
  });

  it('should authenticate valid bearer token', async () => {
    mockRequest.headers = {
      authorization: 'Bearer valid.jwt.token'
    };

    mockJWTService.validateToken.mockResolvedValue({
      valid: true,
      user: {
        id: 'user-123',
        email: 'test@example.com',
        tenantId: 'tenant-123',
        roles: ['user']
      }
    });

    const middleware = authMiddleware();
    await middleware(mockRequest as FastifyRequest, mockReply as FastifyReply);

    expect(mockRequest.user).toEqual({
      id: 'user-123',
      email: 'test@example.com',
      tenantId: 'tenant-123',
      roles: ['user']
    });
  });

  it('should reject request without authorization header', async () => {
    const middleware = authMiddleware();
    await middleware(mockRequest as FastifyRequest, mockReply as FastifyReply);

    expect(mockReply.code).toHaveBeenCalledWith(401);
    expect(mockReply.send).toHaveBeenCalledWith({
      error: 'Unauthorized',
      message: 'Missing authorization header'
    });
  });

  it('should reject request with invalid token format', async () => {
    mockRequest.headers = {
      authorization: 'InvalidFormat token'
    };

    const middleware = authMiddleware();
    await middleware(mockRequest as FastifyRequest, mockReply as FastifyReply);

    expect(mockReply.code).toHaveBeenCalledWith(401);
    expect(mockReply.send).toHaveBeenCalledWith({
      error: 'Unauthorized',
      message: 'Invalid authorization header format'
    });
  });

  it('should reject request with invalid token', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid.jwt.token'
    };

    mockJWTService.validateToken.mockResolvedValue({
      valid: false,
      error: 'Token expired'
    });

    const middleware = authMiddleware();
    await middleware(mockRequest as FastifyRequest, mockReply as FastifyReply);

    expect(mockReply.code).toHaveBeenCalledWith(401);
    expect(mockReply.send).toHaveBeenCalledWith({
      error: 'Unauthorized',
      message: 'Token expired'
    });
  });
});
```

### 11.1.2 Authorization Tests

Unit tests for role-based access control and permission checking.

```typescript
// tests/unit/auth/permissionService.test.ts
import { describe, it, expect, beforeEach } from '@jest/globals';
import { PermissionService } from '../../../src/services/permissionService';

describe('Permission Service', () => {
  let permissionService: PermissionService;

  beforeEach(() => {
    permissionService = new PermissionService();
  });

  describe('checkPermission', () => {
    it('should grant access with exact permission match', () => {
      const userPermissions = ['read:users:tenant', 'write:users:tenant'];
      const requiredPermission = 'read:users:tenant';

      const hasPermission = permissionService.checkPermission(
        userPermissions,
        requiredPermission
      );

      expect(hasPermission).toBe(true);
    });

    it('should grant access with wildcard permissions', () => {
      const userPermissions = ['*:*:*'];
      const requiredPermission = 'delete:users:tenant';

      const hasPermission = permissionService.checkPermission(
        userPermissions,
        requiredPermission
      );

      expect(hasPermission).toBe(true);
    });

    it('should grant access with partial wildcard permissions', () => {
      const userPermissions = ['read:*:tenant'];
      const requiredPermission = 'read:users:tenant';

      const hasPermission = permissionService.checkPermission(
        userPermissions,
        requiredPermission
      );

      expect(hasPermission).toBe(true);
    });

    it('should deny access without matching permissions', () => {
      const userPermissions = ['read:users:tenant'];
      const requiredPermission = 'delete:users:tenant';

      const hasPermission = permissionService.checkPermission(
        userPermissions,
        requiredPermission
      );

      expect(hasPermission).toBe(false);
    });

    it('should handle empty permission arrays', () => {
      const userPermissions: string[] = [];
      const requiredPermission = 'read:users:tenant';

      const hasPermission = permissionService.checkPermission(
        userPermissions,
        requiredPermission
      );

      expect(hasPermission).toBe(false);
    });
  });

  describe('parsePermission', () => {
    it('should parse valid permission string', () => {
      const permission = 'read:users:tenant';
      const parsed = permissionService.parsePermission(permission);

      expect(parsed).toEqual({
        action: 'read',
        resource: 'users',
        scope: 'tenant'
      });
    });

    it('should handle wildcard permissions', () => {
      const permission = '*:*:*';
      const parsed = permissionService.parsePermission(permission);

      expect(parsed).toEqual({
        action: '*',
        resource: '*',
        scope: '*'
      });
    });

    it('should throw error for invalid permission format', () => {
      const permission = 'invalid-permission';

      expect(() => {
        permissionService.parsePermission(permission);
      }).toThrow('Invalid permission format');
    });
  });
});
```

### 11.1.3 Business Logic Tests

Unit tests for core business logic components.

```typescript
// tests/unit/services/tenantService.test.ts
import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { TenantService } from '../../../src/services/tenantService';
import { MongoClient, Db, Collection } from 'mongodb';

jest.mock('mongodb');

describe('Tenant Service', () => {
  let tenantService: TenantService;
  let mockDb: jest.Mocked<Db>;
  let mockCollection: jest.Mocked<Collection>;

  beforeEach(() => {
    mockCollection = {
      insertOne: jest.fn(),
      findOne: jest.fn(),
      find: jest.fn(),
      updateOne: jest.fn(),
      deleteOne: jest.fn(),
      countDocuments: jest.fn()
    } as any;

    mockDb = {
      collection: jest.fn().mockReturnValue(mockCollection)
    } as any;

    tenantService = new TenantService(mockDb);
  });

  describe('createTenant', () => {
    it('should create a new tenant successfully', async () => {
      const tenantData = {
        name: 'Test Tenant',
        domain: 'test.example.com',
        adminEmail: 'admin@test.example.com'
      };

      mockCollection.findOne.mockResolvedValue(null); // No existing tenant
      mockCollection.insertOne.mockResolvedValue({ insertedId: 'new-id' } as any);

      const result = await tenantService.createTenant(tenantData);

      expect(result).toMatchObject({
        name: 'Test Tenant',
        domain: 'test.example.com',
        status: 'active'
      });
      expect(result.tenantId).toBeDefined();
      expect(mockCollection.insertOne).toHaveBeenCalled();
    });

    it('should reject duplicate domain', async () => {
      const tenantData = {
        name: 'Test Tenant',
        domain: 'existing.example.com',
        adminEmail: 'admin@test.example.com'
      };

      mockCollection.findOne.mockResolvedValue({ domain: 'existing.example.com' });

      await expect(tenantService.createTenant(tenantData)).rejects.toThrow(
        'Domain already exists'
      );
    });

    it('should generate unique tenant ID', async () => {
      const tenantData = {
        name: 'Test Tenant',
        adminEmail: 'admin@test.example.com'
      };

      mockCollection.findOne.mockResolvedValue(null);
      mockCollection.insertOne.mockResolvedValue({ insertedId: 'new-id' } as any);

      const result = await tenantService.createTenant(tenantData);

      expect(result.tenantId).toMatch(/^tenant_\d+_[a-z0-9]+$/);
    });
  });

  describe('getTenant', () => {
    it('should retrieve tenant by ID', async () => {
      const mockTenant = {
        _id: 'object-id',
        tenantId: 'tenant-123',
        name: 'Test Tenant',
        status: 'active'
      };

      mockCollection.findOne.mockResolvedValue(mockTenant);

      const result = await tenantService.getTenant('tenant-123');

      expect(result).toEqual(mockTenant);
      expect(mockCollection.findOne).toHaveBeenCalledWith({ tenantId: 'tenant-123' });
    });

    it('should return null for non-existent tenant', async () => {
      mockCollection.findOne.mockResolvedValue(null);

      const result = await tenantService.getTenant('non-existent');

      expect(result).toBeNull();
    });
  });

  describe('updateTenant', () => {
    it('should update tenant successfully', async () => {
      const updateData = {
        name: 'Updated Tenant Name',
        settings: {
          maxUsers: 100
        }
      };

      mockCollection.updateOne.mockResolvedValue({ modifiedCount: 1 } as any);
      mockCollection.findOne.mockResolvedValue({
        tenantId: 'tenant-123',
        ...updateData,
        updatedAt: new Date()
      });

      const result = await tenantService.updateTenant('tenant-123', updateData);

      expect(result).toMatchObject(updateData);
      expect(mockCollection.updateOne).toHaveBeenCalledWith(
        { tenantId: 'tenant-123' },
        { $set: { ...updateData, updatedAt: expect.any(Date) } }
      );
    });

    it('should throw error for non-existent tenant', async () => {
      mockCollection.updateOne.mockResolvedValue({ modifiedCount: 0 } as any);

      await expect(
        tenantService.updateTenant('non-existent', { name: 'New Name' })
      ).rejects.toThrow('Tenant not found');
    });
  });

  describe('validateTenantLimits', () => {
    it('should validate within limits', async () => {
      const mockTenant = {
        tenantId: 'tenant-123',
        settings: {
          maxUsers: 10,
          billing: { maxApiCalls: 1000 }
        }
      };

      mockCollection.findOne.mockResolvedValue(mockTenant);
      mockCollection.countDocuments
        .mockResolvedValueOnce(5) // Current users
        .mockResolvedValueOnce(500); // Current API calls

      const result = await tenantService.validateTenantLimits('tenant-123');

      expect(result.withinLimits).toBe(true);
      expect(result.usage).toEqual({
        users: { current: 5, max: 10 },
        apiCalls: { current: 500, max: 1000 }
      });
    });

    it('should detect limit violations', async () => {
      const mockTenant = {
        tenantId: 'tenant-123',
        settings: {
          maxUsers: 5,
          billing: { maxApiCalls: 1000 }
        }
      };

      mockCollection.findOne.mockResolvedValue(mockTenant);
      mockCollection.countDocuments
        .mockResolvedValueOnce(10) // Exceeds user limit
        .mockResolvedValueOnce(1500); // Exceeds API call limit

      const result = await tenantService.validateTenantLimits('tenant-123');

      expect(result.withinLimits).toBe(false);
      expect(result.violations).toContain('User limit exceeded');
      expect(result.violations).toContain('API call limit exceeded');
    });
  });
});
```

## 11.2 Integration Testing

### 11.2.1 API Endpoint Tests

Integration tests for API endpoints with real database connections.

```typescript
// tests/integration/api/auth.test.ts
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { FastifyInstance } from 'fastify';
import { MongoClient, Db } from 'mongodb';
import { buildApp } from '../../../src/app';
import { setupTestDatabase, cleanupTestDatabase } from '../../helpers/database';

describe('Authentication API Integration', () => {
  let app: FastifyInstance;
  let mongoClient: MongoClient;
  let db: Db;

  beforeAll(async () => {
    const { client, database } = await setupTestDatabase();
    mongoClient = client;
    db = database;
    
    app = buildApp({
      mongodb: { client: mongoClient, db },
      cognito: {
        userPoolId: process.env.TEST_COGNITO_USER_POOL_ID!,
        clientId: process.env.TEST_COGNITO_CLIENT_ID!,
        region: 'us-east-1'
      }
    });

    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await cleanupTestDatabase(mongoClient);
  });

  beforeEach(async () => {
    // Clean up test data
    await db.collection('users').deleteMany({});
    await db.collection('tenants').deleteMany({});
  });

  describe('POST /auth/login', () => {
    it('should authenticate valid user credentials', async () => {
      // Setup test tenant and user
      await db.collection('tenants').insertOne({
        tenantId: 'test-tenant',
        name: 'Test Tenant',
        status: 'active'
      });

      await db.collection('users').insertOne({
        tenantId: 'test-tenant',
        email: 'test@example.com',
        cognitoUserId: 'test-cognito-user',
        roles: ['user'],
        status: 'active'
      });

      const response = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'test@example.com',
          password: 'TestPassword123!'
        }
      });

      expect(response.statusCode).toBe(200);
      
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(body.data).toHaveProperty('accessToken');
      expect(body.data).toHaveProperty('refreshToken');
      expect(body.data.user).toMatchObject({
        email: 'test@example.com',
        tenantId: 'test-tenant'
      });
    });

    it('should reject invalid credentials', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'invalid@example.com',
          password: 'wrongpassword'
        }
      });

      expect(response.statusCode).toBe(401);
      
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Authentication failed');
    });

    it('should validate request payload', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'invalid-email',
          // Missing password
        }
      });

      expect(response.statusCode).toBe(400);
      
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Validation Error');
    });
  });

  describe('POST /auth/refresh', () => {
    it('should refresh valid token', async () => {
      // First login to get refresh token
      const loginResponse = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'test@example.com',
          password: 'TestPassword123!'
        }
      });

      const loginBody = JSON.parse(loginResponse.body);
      const refreshToken = loginBody.data.refreshToken;

      const response = await app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: {
          refreshToken
        }
      });

      expect(response.statusCode).toBe(200);
      
      const body = JSON.parse(response.body);
      expect(body.data).toHaveProperty('accessToken');
      expect(body.data).toHaveProperty('refreshToken');
    });

    it('should reject invalid refresh token', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: {
          refreshToken: 'invalid-refresh-token'
        }
      });

      expect(response.statusCode).toBe(401);
    });
  });
});
```

### 11.2.2 Database Integration Tests

Tests for database operations and data consistency.

```typescript
// tests/integration/database/tenantOperations.test.ts
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { MongoClient, Db } from 'mongodb';
import { TenantService } from '../../../src/services/tenantService';
import { UserService } from '../../../src/services/userService';
import { setupTestDatabase, cleanupTestDatabase } from '../../helpers/database';

describe('Tenant Database Operations', () => {
  let mongoClient: MongoClient;
  let db: Db;
  let tenantService: TenantService;
  let userService: UserService;

  beforeAll(async () => {
    const { client, database } = await setupTestDatabase();
    mongoClient = client;
    db = database;
    
    tenantService = new TenantService(db);
    userService = new UserService(db, 'test-tenant');
  });

  afterAll(async () => {
    await cleanupTestDatabase(mongoClient);
  });

  beforeEach(async () => {
    await db.collection('tenants').deleteMany({});
    await db.collection('users').deleteMany({});
    await db.collection('roles').deleteMany({});
  });

  describe('Tenant Creation with Dependencies', () => {
    it('should create tenant with default roles and admin user', async () => {
      const tenantData = {
        name: 'Integration Test Tenant',
        domain: 'integration.test.com',
        adminEmail: 'admin@integration.test.com'
      };

      const tenant = await tenantService.createTenant(tenantData);

      // Verify tenant creation
      expect(tenant).toMatchObject({
        name: tenantData.name,
        domain: tenantData.domain,
        status: 'active'
      });

      // Verify default roles were created
      const roles = await db.collection('roles').find({
        tenantId: tenant.tenantId
      }).toArray();

      expect(roles).toHaveLength(3); // admin, user, viewer
      expect(roles.map(r => r.name)).toContain('admin');
      expect(roles.map(r => r.name)).toContain('user');
      expect(roles.map(r => r.name)).toContain('viewer');

      // Verify admin user was created
      const adminUser = await db.collection('users').findOne({
        tenantId: tenant.tenantId,
        email: tenantData.adminEmail
      });

      expect(adminUser).toBeTruthy();
      expect(adminUser?.roles).toContain('admin');
    });

    it('should maintain data isolation between tenants', async () => {
      // Create two tenants
      const tenant1 = await tenantService.createTenant({
        name: 'Tenant 1',
        adminEmail: 'admin1@test.com'
      });

      const tenant2 = await tenantService.createTenant({
        name: 'Tenant 2',
        adminEmail: 'admin2@test.com'
      });

      // Create users for each tenant
      const userService1 = new UserService(db, tenant1.tenantId);
      const userService2 = new UserService(db, tenant2.tenantId);

      await userService1.create({
        email: 'user1@test.com',
        cognitoUserId: 'cognito-user-1',
        profile: { firstName: 'User', lastName: 'One' },
        roles: ['user'],
        status: 'active'
      });

      await userService2.create({
        email: 'user2@test.com',
        cognitoUserId: 'cognito-user-2',
        profile: { firstName: 'User', lastName: 'Two' },
        roles: ['user'],
        status: 'active'
      });

      // Verify isolation - tenant1 service should only see tenant1 users
      const tenant1Users = await userService1.list();
      expect(tenant1Users.users).toHaveLength(2); // admin + user1
      expect(tenant1Users.users.map(u => u.email)).toContain('admin1@test.com');
      expect(tenant1Users.users.map(u => u.email)).toContain('user1@test.com');
      expect(tenant1Users.users.map(u => u.email)).not.toContain('user2@test.com');

      // Verify isolation - tenant2 service should only see tenant2 users
      const tenant2Users = await userService2.list();
      expect(tenant2Users.users).toHaveLength(2); // admin + user2
      expect(tenant2Users.users.map(u => u.email)).toContain('admin2@test.com');
      expect(tenant2Users.users.map(u => u.email)).toContain('user2@test.com');
      expect(tenant2Users.users.map(u => u.email)).not.toContain('user1@test.com');
    });
  });

  describe('Transaction Consistency', () => {
    it('should rollback on tenant creation failure', async () => {
      // Mock a failure scenario
      const originalInsertOne = db.collection('users').insertOne;
      
      // Make user creation fail after tenant is created
      db.collection('users').insertOne = jest.fn().mockRejectedValue(
        new Error('User creation failed')
      );

      try {
        await tenantService.createTenant({
          name: 'Failed Tenant',
          adminEmail: 'admin@failed.com'
        });
        
        // Should not reach here
        expect(true).toBe(false);
      } catch (error) {
        expect(error.message).toContain('User creation failed');
      }

      // Verify tenant was not created (rollback occurred)
      const tenants = await db.collection('tenants').find({
        name: 'Failed Tenant'
      }).toArray();
      
      expect(tenants).toHaveLength(0);

      // Restore original method
      db.collection('users').insertOne = originalInsertOne;
    });
  });
});
```

### 11.2.3 External Service Integration Tests

Tests for integration with external services like AWS Cognito.

```typescript
// tests/integration/external/cognitoIntegration.test.ts
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { CognitoService } from '../../../src/services/cognitoService';
import { CognitoIdentityServiceProvider } from 'aws-sdk';

describe('Cognito Integration', () => {
  let cognitoService: CognitoService;
  let testUserEmail: string;
  let testUserId: string;

  beforeAll(() => {
    cognitoService = new CognitoService({
      userPoolId: process.env.TEST_COGNITO_USER_POOL_ID!,
      clientId: process.env.TEST_COGNITO_CLIENT_ID!,
      clientSecret: process.env.TEST_COGNITO_CLIENT_SECRET!,
      region: 'us-east-1'
    });

    testUserEmail = `test-${Date.now()}@example.com`;
  });

  afterAll(async () => {
    // Cleanup test user
    if (testUserId) {
      try {
        await cognitoService.deleteUser(testUserId);
      } catch (error) {
        console.warn('Failed to cleanup test user:', error);
      }
    }
  });

  describe('User Management', () => {
    it('should create user in Cognito', async () => {
      const userData = {
        email: testUserEmail,
        temporaryPassword: 'TempPass123!',
        tenantId: 'test-tenant',
        roles: ['user']
      };

      const result = await cognitoService.createUser(userData);

      expect(result.userId).toBeDefined();
      expect(result.email).toBe(testUserEmail);
      
      testUserId = result.userId;
    });

    it('should authenticate user with valid credentials', async () => {
      // First set permanent password
      await cognitoService.setUserPassword(testUserId, 'NewPassword123!');

      const authResult = await cognitoService.authenticateUser(
        testUserEmail,
        'NewPassword123!'
      );

      expect(authResult.AccessToken).toBeDefined();
      expect(authResult.IdToken).toBeDefined();
      expect(authResult.RefreshToken).toBeDefined();
    });

    it('should update user attributes', async () => {
      const updates = {
        'custom:tenantId': 'updated-tenant',
        'custom:roles': JSON.stringify(['admin', 'user'])
      };

      await cognitoService.updateUserAttributes(testUserId, updates);

      const user = await cognitoService.getUser(testUserId);
      
      const tenantIdAttr = user.UserAttributes?.find(
        attr => attr.Name === 'custom:tenantId'
      );
      const rolesAttr = user.UserAttributes?.find(
        attr => attr.Name === 'custom:roles'
      );

      expect(tenantIdAttr?.Value).toBe('updated-tenant');
      expect(JSON.parse(rolesAttr?.Value || '[]')).toEqual(['admin', 'user']);
    });

    it('should handle authentication failures gracefully', async () => {
      await expect(
        cognitoService.authenticateUser(testUserEmail, 'WrongPassword')
      ).rejects.toThrow();
    });
  });

  describe('Token Validation', () => {
    it('should validate JWT tokens from Cognito', async () => {
      // Authenticate to get token
      const authResult = await cognitoService.authenticateUser(
        testUserEmail,
        'NewPassword123!'
      );

      // Validate the token
      const validation = await cognitoService.validateToken(authResult.AccessToken);

      expect(validation.valid).toBe(true);
      expect(validation.payload?.email).toBe(testUserEmail);
    });

    it('should reject invalid tokens', async () => {
      const validation = await cognitoService.validateToken('invalid.jwt.token');

      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
    });
  });
});
```

## 11.3 End-to-End Testing

### 11.3.1 User Journey Tests

Complete user journey tests from registration to API usage.

```typescript
// tests/e2e/userJourney.test.ts
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import { buildApp } from '../../src/app';
import { setupTestDatabase, cleanupTestDatabase } from '../helpers/database';

describe('Complete User Journey E2E', () => {
  let app: FastifyInstance;
  let mongoClient: MongoClient;
  let accessToken: string;
  let tenantId: string;

  beforeAll(async () => {
    const { client, database } = await setupTestDatabase();
    mongoClient = client;
    
    app = buildApp({
      mongodb: { client: mongoClient, db: database },
      cognito: {
        userPoolId: process.env.TEST_COGNITO_USER_POOL_ID!,
        clientId: process.env.TEST_COGNITO_CLIENT_ID!,
        region: 'us-east-1'
      }
    });

    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await cleanupTestDatabase(mongoClient);
  });

  it('should complete full user journey', async () => {
    // Step 1: Create tenant (admin operation)
    const createTenantResponse = await app.inject({
      method: 'POST',
      url: '/admin/tenants',
      headers: {
        'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
      },
      payload: {
        name: 'E2E Test Company',
        domain: 'e2e-test.com',
        adminEmail: 'admin@e2e-test.com',
        plan: 'basic'
      }
    });

    expect(createTenantResponse.statusCode).toBe(201);
    const tenantData = JSON.parse(createTenantResponse.body);
    tenantId = tenantData.data.tenantId;

    // Step 2: Admin login
    const loginResponse = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'admin@e2e-test.com',
        password: 'TempPassword123!'
      }
    });

    expect(loginResponse.statusCode).toBe(200);
    const loginData = JSON.parse(loginResponse.body);
    accessToken = loginData.data.accessToken;

    // Step 3: Create additional user
    const createUserResponse = await app.inject({
      method: 'POST',
      url: '/users',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      payload: {
        email: 'user@e2e-test.com',
        profile: {
          firstName: 'Test',
          lastName: 'User'
        },
        roles: ['user']
      }
    });

    expect(createUserResponse.statusCode).toBe(201);

    // Step 4: Create custom role
    const createRoleResponse = await app.inject({
      method: 'POST',
      url: '/roles',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      payload: {
        name: 'data-analyst',
        description: 'Data analysis role',
        permissions: [
          'read:users:tenant',
          'read:analytics:tenant',
          'execute:reports:tenant'
        ]
      }
    });

    expect(createRoleResponse.statusCode).toBe(201);

    // Step 5: Assign role to user
    const assignRoleResponse = await app.inject({
      method: 'PUT',
      url: '/users/user@e2e-test.com/roles',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      payload: {
        roles: ['user', 'data-analyst']
      }
    });

    expect(assignRoleResponse.statusCode).toBe(200);

    // Step 6: User login with new role
    const userLoginResponse = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'user@e2e-test.com',
        password: 'TempPassword123!'
      }
    });

    expect(userLoginResponse.statusCode).toBe(200);
    const userLoginData = JSON.parse(userLoginResponse.body);
    const userToken = userLoginData.data.accessToken;

    // Step 7: Test permission-based access
    const analyticsResponse = await app.inject({
      method: 'GET',
      url: '/analytics/dashboard',
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    });

    expect(analyticsResponse.statusCode).toBe(200);

    // Step 8: Test forbidden access
    const adminOnlyResponse = await app.inject({
      method: 'GET',
      url: '/admin/system-stats',
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    });

    expect(adminOnlyResponse.statusCode).toBe(403);

    // Step 9: Generate API key
    const apiKeyResponse = await app.inject({
      method: 'POST',
      url: '/api-keys',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      payload: {
        name: 'E2E Test API Key',
        permissions: ['read:users:tenant'],
        expiresIn: '30d'
      }
    });

    expect(apiKeyResponse.statusCode).toBe(201);
    const apiKeyData = JSON.parse(apiKeyResponse.body);

    // Step 10: Use API key for authentication
    const apiKeyUsageResponse = await app.inject({
      method: 'GET',
      url: '/users',
      headers: {
        'X-API-Key': apiKeyData.data.key
      }
    });

    expect(apiKeyUsageResponse.statusCode).toBe(200);

    // Step 11: Test rate limiting
    const rateLimitPromises = Array.from({ length: 15 }, () =>
      app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'X-API-Key': apiKeyData.data.key
        }
      })
    );

    const rateLimitResponses = await Promise.all(rateLimitPromises);
    const rateLimitedResponses = rateLimitResponses.filter(
      response => response.statusCode === 429
    );

    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });
});
```

### 11.3.2 Multi-Tenant Scenarios

Tests for multi-tenant isolation and cross-tenant security.

```typescript
// tests/e2e/multiTenant.test.ts
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import { buildApp } from '../../src/app';
import { setupTestDatabase, cleanupTestDatabase } from '../helpers/database';

describe('Multi-Tenant E2E Scenarios', () => {
  let app: FastifyInstance;
  let mongoClient: MongoClient;
  let tenant1Token: string;
  let tenant2Token: string;
  let tenant1Id: string;
  let tenant2Id: string;

  beforeAll(async () => {
    const { client, database } = await setupTestDatabase();
    mongoClient = client;
    
    app = buildApp({
      mongodb: { client: mongoClient, db: database },
      cognito: {
        userPoolId: process.env.TEST_COGNITO_USER_POOL_ID!,
        clientId: process.env.TEST_COGNITO_CLIENT_ID!,
        region: 'us-east-1'
      }
    });

    await app.ready();

    // Setup two tenants
    await setupTenants();
  });

  afterAll(async () => {
    await app.close();
    await cleanupTestDatabase(mongoClient);
  });

  async function setupTenants() {
    // Create tenant 1
    const tenant1Response = await app.inject({
      method: 'POST',
      url: '/admin/tenants',
      headers: {
        'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
      },
      payload: {
        name: 'Tenant One',
        domain: 'tenant1.test.com',
        adminEmail: 'admin@tenant1.test.com'
      }
    });

    const tenant1Data = JSON.parse(tenant1Response.body);
    tenant1Id = tenant1Data.data.tenantId;

    // Create tenant 2
    const tenant2Response = await app.inject({
      method: 'POST',
      url: '/admin/tenants',
      headers: {
        'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
      },
      payload: {
        name: 'Tenant Two',
        domain: 'tenant2.test.com',
        adminEmail: 'admin@tenant2.test.com'
      }
    });

    const tenant2Data = JSON.parse(tenant2Response.body);
    tenant2Id = tenant2Data.data.tenantId;

    // Login as tenant 1 admin
    const tenant1LoginResponse = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'admin@tenant1.test.com',
        password: 'TempPassword123!'
      }
    });

    const tenant1LoginData = JSON.parse(tenant1LoginResponse.body);
    tenant1Token = tenant1LoginData.data.accessToken;

    // Login as tenant 2 admin
    const tenant2LoginResponse = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'admin@tenant2.test.com',
        password: 'TempPassword123!'
      }
    });

    const tenant2LoginData = JSON.parse(tenant2LoginResponse.body);
    tenant2Token = tenant2LoginData.data.accessToken;
  }

  describe('Data Isolation', () => {
    it('should isolate user data between tenants', async () => {
      // Create user in tenant 1
      await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        },
        payload: {
          email: 'user1@tenant1.test.com',
          profile: { firstName: 'User', lastName: 'One' },
          roles: ['user']
        }
      });

      // Create user in tenant 2
      await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${tenant2Token}`
        },
        payload: {
          email: 'user1@tenant2.test.com',
          profile: { firstName: 'User', lastName: 'Two' },
          roles: ['user']
        }
      });

      // Tenant 1 should only see their users
      const tenant1UsersResponse = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        }
      });

      const tenant1Users = JSON.parse(tenant1UsersResponse.body);
      expect(tenant1Users.data.users).toHaveLength(2); // admin + user1
      expect(tenant1Users.data.users.map(u => u.email)).toContain('admin@tenant1.test.com');
      expect(tenant1Users.data.users.map(u => u.email)).toContain('user1@tenant1.test.com');
      expect(tenant1Users.data.users.map(u => u.email)).not.toContain('user1@tenant2.test.com');

      // Tenant 2 should only see their users
      const tenant2UsersResponse = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${tenant2Token}`
        }
      });

      const tenant2Users = JSON.parse(tenant2UsersResponse.body);
      expect(tenant2Users.data.users).toHaveLength(2); // admin + user1
      expect(tenant2Users.data.users.map(u => u.email)).toContain('admin@tenant2.test.com');
      expect(tenant2Users.data.users.map(u => u.email)).toContain('user1@tenant2.test.com');
      expect(tenant2Users.data.users.map(u => u.email)).not.toContain('user1@tenant1.test.com');
    });

    it('should prevent cross-tenant data access', async () => {
      // Try to access tenant 2 user from tenant 1 context
      const crossTenantResponse = await app.inject({
        method: 'GET',
        url: '/users/user1@tenant2.test.com',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        }
      });

      expect(crossTenantResponse.statusCode).toBe(404);
    });
  });

  describe('Role Isolation', () => {
    it('should isolate roles between tenants', async () => {
      // Create custom role in tenant 1
      await app.inject({
        method: 'POST',
        url: '/roles',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        },
        payload: {
          name: 'custom-role',
          permissions: ['read:users:tenant']
        }
      });

      // Create different custom role in tenant 2
      await app.inject({
        method: 'POST',
        url: '/roles',
        headers: {
          'Authorization': `Bearer ${tenant2Token}`
        },
        payload: {
          name: 'custom-role',
          permissions: ['write:users:tenant']
        }
      });

      // Verify tenant 1 role
      const tenant1RolesResponse = await app.inject({
        method: 'GET',
        url: '/roles/custom-role',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        }
      });

      const tenant1Role = JSON.parse(tenant1RolesResponse.body);
      expect(tenant1Role.data.permissions).toEqual(['read:users:tenant']);

      // Verify tenant 2 role
      const tenant2RolesResponse = await app.inject({
        method: 'GET',
        url: '/roles/custom-role',
        headers: {
          'Authorization': `Bearer ${tenant2Token}`
        }
      });

      const tenant2Role = JSON.parse(tenant2RolesResponse.body);
      expect(tenant2Role.data.permissions).toEqual(['write:users:tenant']);
    });
  });

  describe('API Key Isolation', () => {
    it('should isolate API keys between tenants', async () => {
      // Create API key for tenant 1
      const tenant1ApiKeyResponse = await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: {
          'Authorization': `Bearer ${tenant1Token}`
        },
        payload: {
          name: 'Tenant 1 API Key',
          permissions: ['read:users:tenant']
        }
      });

      const tenant1ApiKey = JSON.parse(tenant1ApiKeyResponse.body);

      // Try to use tenant 1 API key to access tenant 2 data
      const crossTenantApiResponse = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'X-API-Key': tenant1ApiKey.data.key,
          'X-Tenant-ID': tenant2Id // Try to override tenant
        }
      });

      // Should still only return tenant 1 data
      const users = JSON.parse(crossTenantApiResponse.body);
      expect(users.data.users.map(u => u.email)).not.toContain('admin@tenant2.test.com');
    });
  });
});
```

### 11.3.3 Security Testing

Security-focused end-to-end tests.

```typescript
// tests/e2e/security.test.ts
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import { buildApp } from '../../src/app';
import { setupTestDatabase, cleanupTestDatabase } from '../helpers/database';

describe('Security E2E Tests', () => {
  let app: FastifyInstance;
  let mongoClient: MongoClient;
  let validToken: string;

  beforeAll(async () => {
    const { client, database } = await setupTestDatabase();
    mongoClient = client;
    
    app = buildApp({
      mongodb: { client: mongoClient, db: database },
      cognito: {
        userPoolId: process.env.TEST_COGNITO_USER_POOL_ID!,
        clientId: process.env.TEST_COGNITO_CLIENT_ID!,
        region: 'us-east-1'
      }
    });

    await app.ready();

    // Setup test user and get token
    await setupTestUser();
  });

  afterAll(async () => {
    await app.close();
    await cleanupTestDatabase(mongoClient);
  });

  async function setupTestUser() {
    // Create tenant and user for testing
    const tenantResponse = await app.inject({
      method: 'POST',
      url: '/admin/tenants',
      headers: {
        'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
      },
      payload: {
        name: 'Security Test Tenant',
        adminEmail: 'admin@security.test.com'
      }
    });

    const loginResponse = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'admin@security.test.com',
        password: 'TempPassword123!'
      }
    });

    const loginData = JSON.parse(loginResponse.body);
    validToken = loginData.data.accessToken;
  }

  describe('Authentication Security', () => {
    it('should reject requests without authentication', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/users'
      });

      expect(response.statusCode).toBe(401);
    });

    it('should reject requests with invalid tokens', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'Authorization': 'Bearer invalid.jwt.token'
        }
      });

      expect(response.statusCode).toBe(401);
    });

    it('should reject requests with expired tokens', async () => {
      // This would require a pre-generated expired token
      const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid';
      
      const response = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${expiredToken}`
        }
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('Authorization Security', () => {
    it('should enforce role-based access control', async () => {
      // Create user with limited permissions
      await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        },
        payload: {
          email: 'limited@security.test.com',
          profile: { firstName: 'Limited', lastName: 'User' },
          roles: ['viewer'] // Only read permissions
        }
      });

      // Login as limited user
      const limitedLoginResponse = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'limited@security.test.com',
          password: 'TempPassword123!'
        }
      });

      const limitedLoginData = JSON.parse(limitedLoginResponse.body);
      const limitedToken = limitedLoginData.data.accessToken;

      // Try to create user (should fail)
      const createUserResponse = await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${limitedToken}`
        },
        payload: {
          email: 'new@security.test.com',
          profile: { firstName: 'New', lastName: 'User' },
          roles: ['user']
        }
      });

      expect(createUserResponse.statusCode).toBe(403);
    });

    it('should prevent privilege escalation', async () => {
      // Create user with user role
      await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        },
        payload: {
          email: 'regular@security.test.com',
          profile: { firstName: 'Regular', lastName: 'User' },
          roles: ['user']
        }
      });

      // Login as regular user
      const userLoginResponse = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'regular@security.test.com',
          password: 'TempPassword123!'
        }
      });

      const userLoginData = JSON.parse(userLoginResponse.body);
      const userToken = userLoginData.data.accessToken;

      // Try to assign admin role to self (should fail)
      const escalationResponse = await app.inject({
        method: 'PUT',
        url: '/users/regular@security.test.com/roles',
        headers: {
          'Authorization': `Bearer ${userToken}`
        },
        payload: {
          roles: ['admin', 'user']
        }
      });

      expect(escalationResponse.statusCode).toBe(403);
    });
  });

  describe('Input Validation Security', () => {
    it('should prevent SQL injection attempts', async () => {
      const maliciousPayload = {
        email: "'; DROP TABLE users; --",
        profile: { firstName: 'Malicious', lastName: 'User' },
        roles: ['user']
      };

      const response = await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        },
        payload: maliciousPayload
      });

      expect(response.statusCode).toBe(400);
    });

    it('should prevent XSS attempts', async () => {
      const xssPayload = {
        email: 'xss@security.test.com',
        profile: { 
          firstName: '<script>alert("xss")</script>',
          lastName: 'User'
        },
        roles: ['user']
      };

      const response = await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        },
        payload: xssPayload
      });

      expect(response.statusCode).toBe(400);
    });

    it('should enforce request size limits', async () => {
      const largePayload = {
        email: 'large@security.test.com',
        profile: { 
          firstName: 'A'.repeat(10000), // Very large string
          lastName: 'User'
        },
        roles: ['user']
      };

      const response = await app.inject({
        method: 'POST',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        },
        payload: largePayload
      });

      expect(response.statusCode).toBe(413); // Payload too large
    });
  });

  describe('Rate Limiting Security', () => {
    it('should enforce rate limits', async () => {
      const requests = Array.from({ length: 20 }, () =>
        app.inject({
          method: 'GET',
          url: '/users',
          headers: {
            'Authorization': `Bearer ${validToken}`
          }
        })
      );

      const responses = await Promise.all(requests);
      const rateLimitedResponses = responses.filter(r => r.statusCode === 429);

      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('should include rate limit headers', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/users',
        headers: {
          'Authorization': `Bearer ${validToken}`
        }
      });

      expect(response.headers['x-ratelimit-limit']).toBeDefined();
      expect(response.headers['x-ratelimit-remaining']).toBeDefined();
      expect(response.headers['x-ratelimit-reset']).toBeDefined();
    });
  });
});
```

## Test Configuration and Helpers

```typescript
// tests/helpers/database.ts
import { MongoClient, Db } from 'mongodb';

export async function setupTestDatabase(): Promise<{ client: MongoClient; database: Db }> {
  const client = new MongoClient(process.env.TEST_MONGODB_URI || 'mongodb://localhost:27017');
  await client.connect();
  
  const database = client.db(`test_api_gateway_${Date.now()}`);
  
  // Create indexes for test database
  await createTestIndexes(database);
  
  return { client, database };
}

export async function cleanupTestDatabase(client: MongoClient): Promise<void> {
  const databases = await client.db().admin().listDatabases();
  const testDatabases = databases.databases.filter(db => 
    db.name.startsWith('test_api_gateway_')
  );

  for (const db of testDatabases) {
    await client.db(db.name).dropDatabase();
  }

  await client.close();
}

async function createTestIndexes(db: Db): Promise<void> {
  // Create the same indexes as production
  await db.collection('tenants').createIndexes([
    { key: { tenantId: 1 }, unique: true },
    { key: { domain: 1 }, unique: true, sparse: true }
  ]);

  await db.collection('users').createIndexes([
    { key: { tenantId: 1, email: 1 }, unique: true },
    { key: { cognitoUserId: 1 }, unique: true }
  ]);

  await db.collection('roles').createIndexes([
    { key: { tenantId: 1, name: 1 }, unique: true }
  ]);
}
```

```json
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**/*'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 30000,
  maxWorkers: 4
};
```

This comprehensive testing strategy covers all aspects of the Multi-Tenant API Gateway, from unit tests to security penetration testing, ensuring robust quality assurance throughout the development lifecycle. 