# Multi-Tenant Data Management (Epic 2)

## 4.1 MongoDB Multi-Tenant Design

### 4.1.1 Data Isolation Strategies

We implement a **Shared Database, Shared Schema** approach with logical isolation using tenant identifiers. This strategy provides the best balance of cost-effectiveness, performance, and security for most use cases.

#### Tenant Isolation Pattern

```javascript
// Every document includes tenantId for logical isolation
const documentSchema = {
  _id: ObjectId,
  tenantId: String, // Required field for all tenant-scoped collections
  // ... other fields
  createdAt: Date,
  updatedAt: Date
};
```

#### Tenant-Aware Query Wrapper

```typescript
// src/services/database.ts
export class TenantAwareDatabase {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  // Automatically inject tenantId into all queries
  collection(name: string, tenantId: string) {
    return new TenantAwareCollection(this.db.collection(name), tenantId);
  }
}

class TenantAwareCollection {
  private collection: Collection;
  private tenantId: string;

  constructor(collection: Collection, tenantId: string) {
    this.collection = collection;
    this.tenantId = tenantId;
  }

  async find(filter: any = {}, options?: any) {
    return this.collection.find(
      { ...filter, tenantId: this.tenantId },
      options
    );
  }

  async findOne(filter: any = {}, options?: any) {
    return this.collection.findOne(
      { ...filter, tenantId: this.tenantId },
      options
    );
  }

  async insertOne(doc: any, options?: any) {
    return this.collection.insertOne(
      { ...doc, tenantId: this.tenantId, createdAt: new Date() },
      options
    );
  }

  async insertMany(docs: any[], options?: any) {
    const tenantDocs = docs.map(doc => ({
      ...doc,
      tenantId: this.tenantId,
      createdAt: new Date()
    }));
    return this.collection.insertMany(tenantDocs, options);
  }

  async updateOne(filter: any, update: any, options?: any) {
    return this.collection.updateOne(
      { ...filter, tenantId: this.tenantId },
      { ...update, $set: { ...update.$set, updatedAt: new Date() } },
      options
    );
  }

  async updateMany(filter: any, update: any, options?: any) {
    return this.collection.updateMany(
      { ...filter, tenantId: this.tenantId },
      { ...update, $set: { ...update.$set, updatedAt: new Date() } },
      options
    );
  }

  async deleteOne(filter: any, options?: any) {
    return this.collection.deleteOne(
      { ...filter, tenantId: this.tenantId },
      options
    );
  }

  async deleteMany(filter: any, options?: any) {
    return this.collection.deleteMany(
      { ...filter, tenantId: this.tenantId },
      options
    );
  }

  async countDocuments(filter: any = {}, options?: any) {
    return this.collection.countDocuments(
      { ...filter, tenantId: this.tenantId },
      options
    );
  }

  async aggregate(pipeline: any[], options?: any) {
    // Inject tenant filter at the beginning of pipeline
    const tenantPipeline = [
      { $match: { tenantId: this.tenantId } },
      ...pipeline
    ];
    return this.collection.aggregate(tenantPipeline, options);
  }
}
```

### 4.1.2 Collection Schema Design

#### Core Collections

```typescript
// src/models/schemas.ts

// Tenants Collection (Global - no tenantId)
export interface TenantSchema {
  _id: ObjectId;
  tenantId: string; // Unique identifier
  name: string;
  domain?: string;
  settings: {
    maxUsers: number;
    features: string[];
    customization: {
      logo?: string;
      primaryColor?: string;
      theme?: string;
    };
    billing: {
      plan: 'free' | 'basic' | 'premium' | 'enterprise';
      maxApiCalls: number;
      billingEmail: string;
    };
  };
  status: 'active' | 'suspended' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
}

// Users Collection (Tenant-scoped)
export interface UserSchema {
  _id: ObjectId;
  tenantId: string;
  cognitoUserId: string; // Reference to Cognito user
  email: string;
  profile: {
    firstName: string;
    lastName: string;
    avatar?: string;
    department?: string;
    title?: string;
  };
  roles: string[]; // Array of role IDs
  status: 'active' | 'inactive' | 'pending';
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Roles Collection (Tenant-scoped)
export interface RoleSchema {
  _id: ObjectId;
  tenantId: string;
  name: string;
  description?: string;
  permissions: string[]; // Array of permission strings
  isSystem: boolean; // System roles cannot be deleted
  createdBy: ObjectId; // User ID who created the role
  createdAt: Date;
  updatedAt: Date;
}

// API Keys Collection (Tenant-scoped)
export interface ApiKeySchema {
  _id: ObjectId;
  tenantId: string;
  name: string;
  keyHash: string; // Hashed API key
  permissions: string[];
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
    requestsPerDay: number;
  };
  expiresAt?: Date;
  lastUsedAt?: Date;
  isActive: boolean;
  createdBy: ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

// Audit Logs Collection (Tenant-scoped)
export interface AuditLogSchema {
  _id: ObjectId;
  tenantId: string;
  userId?: ObjectId;
  action: string;
  resource: string;
  resourceId?: string;
  details: any;
  ip: string;
  userAgent: string;
  timestamp: Date;
}
```

### 4.1.3 Tenant-Aware Queries

#### Service Layer Implementation

```typescript
// src/services/baseService.ts
export abstract class BaseService<T> {
  protected collection: Collection<T>;
  protected tenantId: string;

  constructor(db: Db, collectionName: string, tenantId: string) {
    this.collection = db.collection(collectionName);
    this.tenantId = tenantId;
  }

  protected addTenantFilter(filter: any = {}): any {
    return { ...filter, tenantId: this.tenantId };
  }

  protected addTenantData(data: any): any {
    return {
      ...data,
      tenantId: this.tenantId,
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  async findById(id: string | ObjectId): Promise<T | null> {
    return this.collection.findOne(this.addTenantFilter({ _id: new ObjectId(id) }));
  }

  async findMany(filter: any = {}, options: any = {}): Promise<T[]> {
    return this.collection.find(this.addTenantFilter(filter), options).toArray();
  }

  async create(data: Partial<T>): Promise<T> {
    const result = await this.collection.insertOne(this.addTenantData(data) as any);
    return this.findById(result.insertedId) as Promise<T>;
  }

  async updateById(id: string | ObjectId, update: any): Promise<T | null> {
    await this.collection.updateOne(
      this.addTenantFilter({ _id: new ObjectId(id) }),
      { $set: { ...update, updatedAt: new Date() } }
    );
    return this.findById(id);
  }

  async deleteById(id: string | ObjectId): Promise<boolean> {
    const result = await this.collection.deleteOne(
      this.addTenantFilter({ _id: new ObjectId(id) })
    );
    return result.deletedCount > 0;
  }

  async count(filter: any = {}): Promise<number> {
    return this.collection.countDocuments(this.addTenantFilter(filter));
  }
}
```

#### User Service Example

```typescript
// src/services/userService.ts
export class UserService extends BaseService<UserSchema> {
  constructor(db: Db, tenantId: string) {
    super(db, 'users', tenantId);
  }

  async findByEmail(email: string): Promise<UserSchema | null> {
    return this.collection.findOne(this.addTenantFilter({ email }));
  }

  async findByCognitoId(cognitoUserId: string): Promise<UserSchema | null> {
    return this.collection.findOne(this.addTenantFilter({ cognitoUserId }));
  }

  async findByRole(roleName: string): Promise<UserSchema[]> {
    return this.collection.find(this.addTenantFilter({ roles: roleName })).toArray();
  }

  async assignRole(userId: string, roleId: string): Promise<UserSchema | null> {
    await this.collection.updateOne(
      this.addTenantFilter({ _id: new ObjectId(userId) }),
      { 
        $addToSet: { roles: roleId },
        $set: { updatedAt: new Date() }
      }
    );
    return this.findById(userId);
  }

  async removeRole(userId: string, roleId: string): Promise<UserSchema | null> {
    await this.collection.updateOne(
      this.addTenantFilter({ _id: new ObjectId(userId) }),
      { 
        $pull: { roles: roleId },
        $set: { updatedAt: new Date() }
      }
    );
    return this.findById(userId);
  }

  async updateLastLogin(userId: string): Promise<void> {
    await this.collection.updateOne(
      this.addTenantFilter({ _id: new ObjectId(userId) }),
      { $set: { lastLoginAt: new Date(), updatedAt: new Date() } }
    );
  }
}
```

### 4.1.4 Database Indexing Strategy

```typescript
// src/database/indexes.ts
export const createIndexes = async (db: Db) => {
  // Tenants collection indexes
  await db.collection('tenants').createIndexes([
    { key: { tenantId: 1 }, unique: true },
    { key: { domain: 1 }, unique: true, sparse: true },
    { key: { status: 1 } },
    { key: { createdAt: 1 } }
  ]);

  // Users collection indexes
  await db.collection('users').createIndexes([
    { key: { tenantId: 1, email: 1 }, unique: true },
    { key: { tenantId: 1, cognitoUserId: 1 }, unique: true },
    { key: { tenantId: 1, status: 1 } },
    { key: { tenantId: 1, roles: 1 } },
    { key: { tenantId: 1, lastLoginAt: 1 } }
  ]);

  // Roles collection indexes
  await db.collection('roles').createIndexes([
    { key: { tenantId: 1, name: 1 }, unique: true },
    { key: { tenantId: 1, isSystem: 1 } },
    { key: { tenantId: 1, createdAt: 1 } }
  ]);

  // API Keys collection indexes
  await db.collection('apiKeys').createIndexes([
    { key: { tenantId: 1, keyHash: 1 }, unique: true },
    { key: { tenantId: 1, isActive: 1 } },
    { key: { tenantId: 1, expiresAt: 1 } },
    { key: { tenantId: 1, lastUsedAt: 1 } }
  ]);

  // Audit Logs collection indexes
  await db.collection('auditLogs').createIndexes([
    { key: { tenantId: 1, timestamp: -1 } },
    { key: { tenantId: 1, userId: 1, timestamp: -1 } },
    { key: { tenantId: 1, action: 1, timestamp: -1 } },
    { key: { tenantId: 1, resource: 1, timestamp: -1 } },
    // TTL index to automatically delete old logs (optional)
    { key: { timestamp: 1 }, expireAfterSeconds: 31536000 } // 1 year
  ]);
};
```

## 4.2 Tenant Management

### 4.2.1 Tenant Data Model

```typescript
// src/models/tenant.ts
export class TenantModel {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  async createTenant(tenantData: {
    name: string;
    domain?: string;
    adminEmail: string;
    plan?: string;
  }): Promise<TenantSchema> {
    const tenantId = this.generateTenantId();
    
    const tenant: TenantSchema = {
      _id: new ObjectId(),
      tenantId,
      name: tenantData.name,
      domain: tenantData.domain,
      settings: {
        maxUsers: this.getMaxUsersByPlan(tenantData.plan || 'free'),
        features: this.getFeaturesByPlan(tenantData.plan || 'free'),
        customization: {
          theme: 'default'
        },
        billing: {
          plan: (tenantData.plan as any) || 'free',
          maxApiCalls: this.getMaxApiCallsByPlan(tenantData.plan || 'free'),
          billingEmail: tenantData.adminEmail
        }
      },
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.db.collection('tenants').insertOne(tenant);
    
    // Create default admin user
    await this.createDefaultAdminUser(tenantId, tenantData.adminEmail);
    
    // Create default roles
    await this.createDefaultRoles(tenantId);
    
    return tenant;
  }

  private generateTenantId(): string {
    return `tenant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getMaxUsersByPlan(plan: string): number {
    const limits = {
      free: 5,
      basic: 25,
      premium: 100,
      enterprise: -1 // unlimited
    };
    return limits[plan] || limits.free;
  }

  private getFeaturesByPlan(plan: string): string[] {
    const features = {
      free: ['basic_auth', 'basic_rbac'],
      basic: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs'],
      premium: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs', 'sso', 'advanced_analytics'],
      enterprise: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs', 'sso', 'advanced_analytics', 'custom_domains', 'priority_support']
    };
    return features[plan] || features.free;
  }

  private getMaxApiCallsByPlan(plan: string): number {
    const limits = {
      free: 1000,
      basic: 10000,
      premium: 100000,
      enterprise: -1 // unlimited
    };
    return limits[plan] || limits.free;
  }

  private async createDefaultAdminUser(tenantId: string, email: string): Promise<void> {
    // This will be called after Cognito user creation
    const userService = new UserService(this.db, tenantId);
    
    await userService.create({
      email,
      cognitoUserId: '', // Will be updated when Cognito user is created
      profile: {
        firstName: 'Admin',
        lastName: 'User'
      },
      roles: ['admin'],
      status: 'active'
    });
  }

  private async createDefaultRoles(tenantId: string): Promise<void> {
    const roleService = new RoleService(this.db, tenantId);
    
    // Create admin role
    await roleService.create({
      name: 'admin',
      description: 'Full access to all resources',
      permissions: ['*'],
      isSystem: true,
      createdBy: new ObjectId() // System created
    });

    // Create user role
    await roleService.create({
      name: 'user',
      description: 'Basic user access',
      permissions: ['read:profile', 'update:profile'],
      isSystem: true,
      createdBy: new ObjectId() // System created
    });

    // Create viewer role
    await roleService.create({
      name: 'viewer',
      description: 'Read-only access',
      permissions: ['read:*'],
      isSystem: true,
      createdBy: new ObjectId() // System created
    });
  }
}
```

### 4.2.2 Tenant CRUD Operations

```typescript
// src/controllers/tenantController.ts
export class TenantController {
  private tenantModel: TenantModel;

  constructor(db: Db) {
    this.tenantModel = new TenantModel(db);
  }

  // Create new tenant (Superadmin only)
  async createTenant(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { name, domain, adminEmail, plan } = request.body as {
        name: string;
        domain?: string;
        adminEmail: string;
        plan?: string;
      };

      // Validate input
      if (!name || !adminEmail) {
        return reply.code(400).send({
          error: 'Bad Request',
          message: 'Name and admin email are required'
        });
      }

      // Check if domain is already taken
      if (domain) {
        const existingTenant = await this.db.collection('tenants')
          .findOne({ domain });
        
        if (existingTenant) {
          return reply.code(409).send({
            error: 'Conflict',
            message: 'Domain already exists'
          });
        }
      }

      // Create tenant
      const tenant = await this.tenantModel.createTenant({
        name,
        domain,
        adminEmail,
        plan
      });

      return reply.code(201).send({
        success: true,
        data: tenant
      });
    } catch (error) {
      request.log.error('Failed to create tenant:', error);
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Failed to create tenant'
      });
    }
  }

  // Get tenant details
  async getTenant(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { tenantId } = request.params as { tenantId: string };
      
      const tenant = await this.db.collection('tenants')
        .findOne({ tenantId });

      if (!tenant) {
        return reply.code(404).send({
          error: 'Not Found',
          message: 'Tenant not found'
        });
      }

      return reply.send({
        success: true,
        data: tenant
      });
    } catch (error) {
      request.log.error('Failed to get tenant:', error);
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Failed to retrieve tenant'
      });
    }
  }

  // Update tenant
  async updateTenant(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { tenantId } = request.params as { tenantId: string };
      const updateData = request.body as Partial<TenantSchema>;

      // Remove fields that shouldn't be updated directly
      delete updateData._id;
      delete updateData.tenantId;
      delete updateData.createdAt;

      const result = await this.db.collection('tenants').updateOne(
        { tenantId },
        { 
          $set: { 
            ...updateData, 
            updatedAt: new Date() 
          } 
        }
      );

      if (result.matchedCount === 0) {
        return reply.code(404).send({
          error: 'Not Found',
          message: 'Tenant not found'
        });
      }

      const updatedTenant = await this.db.collection('tenants')
        .findOne({ tenantId });

      return reply.send({
        success: true,
        data: updatedTenant
      });
    } catch (error) {
      request.log.error('Failed to update tenant:', error);
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Failed to update tenant'
      });
    }
  }

  // List tenants (Superadmin only)
  async listTenants(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { page = 1, limit = 10, status, search } = request.query as {
        page?: number;
        limit?: number;
        status?: string;
        search?: string;
      };

      const filter: any = {};
      
      if (status) {
        filter.status = status;
      }

      if (search) {
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { domain: { $regex: search, $options: 'i' } }
        ];
      }

      const skip = (page - 1) * limit;
      
      const [tenants, total] = await Promise.all([
        this.db.collection('tenants')
          .find(filter)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray(),
        this.db.collection('tenants').countDocuments(filter)
      ]);

      return reply.send({
        success: true,
        data: {
          tenants,
          pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      request.log.error('Failed to list tenants:', error);
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Failed to list tenants'
      });
    }
  }

  // Suspend tenant
  async suspendTenant(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { tenantId } = request.params as { tenantId: string };
      const { reason } = request.body as { reason?: string };

      const result = await this.db.collection('tenants').updateOne(
        { tenantId },
        { 
          $set: { 
            status: 'suspended',
            suspendedAt: new Date(),
            suspensionReason: reason,
            updatedAt: new Date()
          } 
        }
      );

      if (result.matchedCount === 0) {
        return reply.code(404).send({
          error: 'Not Found',
          message: 'Tenant not found'
        });
      }

      // Log suspension event
      await this.logAuditEvent(tenantId, 'tenant_suspended', { reason });

      return reply.send({
        success: true,
        message: 'Tenant suspended successfully'
      });
    } catch (error) {
      request.log.error('Failed to suspend tenant:', error);
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Failed to suspend tenant'
      });
    }
  }

  private async logAuditEvent(tenantId: string, action: string, details: any) {
    await this.db.collection('auditLogs').insertOne({
      tenantId,
      action,
      resource: 'tenant',
      resourceId: tenantId,
      details,
      timestamp: new Date()
    });
  }
}
```

### 4.2.3 Tenant Configuration Management

```typescript
// src/services/tenantConfigService.ts
export class TenantConfigService {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  async updateSettings(tenantId: string, settings: Partial<TenantSchema['settings']>): Promise<TenantSchema | null> {
    const result = await this.db.collection('tenants').updateOne(
      { tenantId },
      { 
        $set: { 
          'settings': { ...settings },
          updatedAt: new Date()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return null;
    }

    return this.db.collection('tenants').findOne({ tenantId });
  }

  async updateCustomization(tenantId: string, customization: any): Promise<TenantSchema | null> {
    const result = await this.db.collection('tenants').updateOne(
      { tenantId },
      { 
        $set: { 
          'settings.customization': customization,
          updatedAt: new Date()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return null;
    }

    return this.db.collection('tenants').findOne({ tenantId });
  }

  async updateBillingPlan(tenantId: string, plan: string): Promise<TenantSchema | null> {
    const features = this.getFeaturesByPlan(plan);
    const maxUsers = this.getMaxUsersByPlan(plan);
    const maxApiCalls = this.getMaxApiCallsByPlan(plan);

    const result = await this.db.collection('tenants').updateOne(
      { tenantId },
      { 
        $set: { 
          'settings.billing.plan': plan,
          'settings.features': features,
          'settings.maxUsers': maxUsers,
          'settings.billing.maxApiCalls': maxApiCalls,
          updatedAt: new Date()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return null;
    }

    return this.db.collection('tenants').findOne({ tenantId });
  }

  async getTenantLimits(tenantId: string): Promise<{
    maxUsers: number;
    currentUsers: number;
    maxApiCalls: number;
    currentApiCalls: number;
    features: string[];
  } | null> {
    const tenant = await this.db.collection('tenants').findOne({ tenantId });
    
    if (!tenant) {
      return null;
    }

    const currentUsers = await this.db.collection('users')
      .countDocuments({ tenantId, status: 'active' });

    // Get current month API calls (implement based on your tracking method)
    const currentApiCalls = await this.getCurrentMonthApiCalls(tenantId);

    return {
      maxUsers: tenant.settings.maxUsers,
      currentUsers,
      maxApiCalls: tenant.settings.billing.maxApiCalls,
      currentApiCalls,
      features: tenant.settings.features
    };
  }

  private async getCurrentMonthApiCalls(tenantId: string): Promise<number> {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    // This would depend on how you track API calls
    // Could be from audit logs or a separate API usage collection
    return this.db.collection('auditLogs').countDocuments({
      tenantId,
      action: 'api_call',
      timestamp: { $gte: startOfMonth }
    });
  }

  private getFeaturesByPlan(plan: string): string[] {
    const features = {
      free: ['basic_auth', 'basic_rbac'],
      basic: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs'],
      premium: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs', 'sso', 'advanced_analytics'],
      enterprise: ['basic_auth', 'basic_rbac', 'api_keys', 'audit_logs', 'sso', 'advanced_analytics', 'custom_domains', 'priority_support']
    };
    return features[plan] || features.free;
  }

  private getMaxUsersByPlan(plan: string): number {
    const limits = {
      free: 5,
      basic: 25,
      premium: 100,
      enterprise: -1
    };
    return limits[plan] || limits.free;
  }

  private getMaxApiCallsByPlan(plan: string): number {
    const limits = {
      free: 1000,
      basic: 10000,
      premium: 100000,
      enterprise: -1
    };
    return limits[plan] || limits.free;
  }
}
```

## 4.3 Data Migration and Seeding

### 4.3.1 Initial Data Setup

```typescript
// scripts/setup-database.ts
import { MongoClient, Db } from 'mongodb';
import { createIndexes } from '../src/database/indexes';
import { seedInitialData } from './seed-data';

export async function setupDatabase(): Promise<void> {
  const client = new MongoClient(process.env.MONGODB_URI!);
  
  try {
    await client.connect();
    const db = client.db();

    console.log('Creating database indexes...');
    await createIndexes(db);

    console.log('Seeding initial data...');
    await seedInitialData(db);

    console.log('Database setup completed successfully');
  } catch (error) {
    console.error('Database setup failed:', error);
    throw error;
  } finally {
    await client.close();
  }
}

if (require.main === module) {
  setupDatabase().catch(console.error);
}
```

### 4.3.2 Tenant Onboarding Process

```typescript
// src/services/tenantOnboardingService.ts
export class TenantOnboardingService {
  private db: Db;
  private cognitoService: CognitoService;

  constructor(db: Db, cognitoService: CognitoService) {
    this.db = db;
    this.cognitoService = cognitoService;
  }

  async onboardTenant(data: {
    companyName: string;
    adminEmail: string;
    adminPassword: string;
    domain?: string;
    plan?: string;
  }): Promise<{
    tenant: TenantSchema;
    adminUser: UserSchema;
    temporaryPassword: string;
  }> {
    const session = this.db.client.startSession();
    
    try {
      await session.withTransaction(async () => {
        // 1. Create tenant
        const tenantModel = new TenantModel(this.db);
        const tenant = await tenantModel.createTenant({
          name: data.companyName,
          domain: data.domain,
          adminEmail: data.adminEmail,
          plan: data.plan
        });

        // 2. Create Cognito user
        const cognitoUser = await this.cognitoService.createUser({
          email: data.adminEmail,
          password: data.adminPassword,
          attributes: {
            tenantId: tenant.tenantId,
            roles: JSON.stringify(['admin'])
          }
        });

        // 3. Update user with Cognito ID
        const userService = new UserService(this.db, tenant.tenantId);
        const adminUser = await userService.updateByCognitoId(
          cognitoUser.User.Username,
          { cognitoUserId: cognitoUser.User.Username }
        );

        // 4. Send welcome email
        await this.sendWelcomeEmail(data.adminEmail, {
          companyName: data.companyName,
          tenantId: tenant.tenantId,
          loginUrl: `${process.env.ADMIN_PANEL_URL}/login`
        });

        return { tenant, adminUser, temporaryPassword: data.adminPassword };
      });
    } finally {
      await session.endSession();
    }
  }

  private async sendWelcomeEmail(email: string, data: any): Promise<void> {
    // Implement email sending logic
    console.log(`Sending welcome email to ${email}`, data);
  }
}
```

### 4.3.3 Data Migration Scripts

```typescript
// scripts/migrations/001-add-tenant-features.ts
export async function migration001(db: Db): Promise<void> {
  console.log('Running migration: Add tenant features');
  
  // Add features field to existing tenants
  await db.collection('tenants').updateMany(
    { 'settings.features': { $exists: false } },
    {
      $set: {
        'settings.features': ['basic_auth', 'basic_rbac'],
        updatedAt: new Date()
      }
    }
  );
  
  console.log('Migration 001 completed');
}

// scripts/migrate.ts
import { MongoClient } from 'mongodb';
import { migration001 } from './migrations/001-add-tenant-features';

const migrations = [
  migration001
];

export async function runMigrations(): Promise<void> {
  const client = new MongoClient(process.env.MONGODB_URI!);
  
  try {
    await client.connect();
    const db = client.db();

    // Create migrations collection if it doesn't exist
    const migrationsCollection = db.collection('migrations');
    
    for (let i = 0; i < migrations.length; i++) {
      const migrationName = `migration_${String(i + 1).padStart(3, '0')}`;
      
      const existingMigration = await migrationsCollection.findOne({
        name: migrationName
      });
      
      if (!existingMigration) {
        console.log(`Running ${migrationName}...`);
        await migrations[i](db);
        
        await migrationsCollection.insertOne({
          name: migrationName,
          runAt: new Date()
        });
        
        console.log(`${migrationName} completed`);
      } else {
        console.log(`${migrationName} already run, skipping`);
      }
    }
    
    console.log('All migrations completed');
  } finally {
    await client.close();
  }
}

if (require.main === module) {
  runMigrations().catch(console.error);
}
```

## Data Security and Compliance

### 1. Data Encryption
- Encrypt sensitive fields at application level
- Use MongoDB encryption at rest
- Implement field-level encryption for PII

### 2. Data Retention
- Implement automatic cleanup of old audit logs
- Provide data export functionality for compliance
- Support data deletion requests (GDPR compliance)

### 3. Backup Strategy
- Regular automated backups
- Point-in-time recovery capability
- Cross-region backup replication

### 4. Monitoring and Alerting
- Monitor tenant data growth
- Alert on unusual data access patterns
- Track tenant resource usage 