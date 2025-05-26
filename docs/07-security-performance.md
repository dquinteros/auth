# Security & Performance

## 7.1 Security Measures

### 7.1.1 Rate Limiting Implementation

Rate limiting protects the API Gateway from abuse and ensures fair resource usage across tenants.

#### Global Rate Limiting

```javascript
// plugins/rateLimiting.js
const rateLimit = require('@fastify/rate-limit');

const globalRateLimitConfig = {
  max: 1000, // requests
  timeWindow: '1 minute',
  keyGenerator: (request) => {
    return request.ip;
  },
  errorResponseBuilder: (request, context) => {
    return {
      code: 429,
      error: 'Too Many Requests',
      message: `Rate limit exceeded, retry in ${context.ttl} seconds`,
      retryAfter: context.ttl
    };
  }
};

module.exports = globalRateLimitConfig;
```

#### Tenant-Specific Rate Limiting

```javascript
// middleware/tenantRateLimit.js
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);

const tenantRateLimit = async (request, reply) => {
  const tenantId = request.user?.tenantId;
  if (!tenantId) return;

  const key = `rate_limit:tenant:${tenantId}`;
  const window = 60; // 1 minute
  const limit = await getTenantRateLimit(tenantId);

  const current = await redis.incr(key);
  if (current === 1) {
    await redis.expire(key, window);
  }

  if (current > limit) {
    reply.code(429).send({
      error: 'Tenant rate limit exceeded',
      limit,
      window,
      retryAfter: await redis.ttl(key)
    });
    return;
  }

  reply.header('X-RateLimit-Limit', limit);
  reply.header('X-RateLimit-Remaining', Math.max(0, limit - current));
};

const getTenantRateLimit = async (tenantId) => {
  const tenant = await db.collection('tenants').findOne({ tenantId });
  return tenant?.settings?.rateLimit || 100; // default 100 req/min
};

module.exports = tenantRateLimit;
```

#### User-Specific Rate Limiting

```javascript
// middleware/userRateLimit.js
const userRateLimit = async (request, reply) => {
  const userId = request.user?.userId;
  const tenantId = request.user?.tenantId;
  
  if (!userId || !tenantId) return;

  const key = `rate_limit:user:${tenantId}:${userId}`;
  const window = 60;
  const limit = await getUserRateLimit(userId, tenantId);

  const current = await redis.incr(key);
  if (current === 1) {
    await redis.expire(key, window);
  }

  if (current > limit) {
    reply.code(429).send({
      error: 'User rate limit exceeded',
      userId,
      limit,
      retryAfter: await redis.ttl(key)
    });
    return;
  }
};

module.exports = userRateLimit;
```

### 7.1.2 CORS Configuration

Cross-Origin Resource Sharing (CORS) configuration for secure cross-domain requests.

```javascript
// plugins/cors.js
const corsConfig = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Check tenant-specific domains
    checkTenantDomain(origin, callback);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-Tenant-ID'
  ],
  exposedHeaders: [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-Request-ID'
  ]
};

const checkTenantDomain = async (origin, callback) => {
  try {
    const tenant = await db.collection('tenants').findOne({
      'settings.allowedDomains': origin,
      status: 'active'
    });
    
    callback(null, !!tenant);
  } catch (error) {
    callback(error, false);
  }
};

module.exports = corsConfig;
```

### 7.1.3 Request Validation and Sanitization

Input validation and sanitization to prevent injection attacks.

```javascript
// schemas/validation.js
const Joi = require('joi');

const schemas = {
  // User registration
  userRegistration: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required(),
    firstName: Joi.string().min(1).max(50).pattern(/^[a-zA-Z\s]+$/).required(),
    lastName: Joi.string().min(1).max(50).pattern(/^[a-zA-Z\s]+$/).required(),
    tenantId: Joi.string().uuid().required()
  }),

  // Role creation
  roleCreation: Joi.object({
    name: Joi.string().min(1).max(50).pattern(/^[a-zA-Z0-9_-]+$/).required(),
    description: Joi.string().max(200).optional(),
    permissions: Joi.array().items(Joi.string().pattern(/^[a-zA-Z0-9:_-]+$/)).required(),
    tenantId: Joi.string().uuid().required()
  }),

  // API key creation
  apiKeyCreation: Joi.object({
    name: Joi.string().min(1).max(100).required(),
    scopes: Joi.array().items(Joi.string()).required(),
    expiresAt: Joi.date().greater('now').optional(),
    tenantId: Joi.string().uuid().required()
  })
};

// Validation middleware
const validate = (schema) => {
  return async (request, reply) => {
    try {
      const { error, value } = schema.validate(request.body, {
        abortEarly: false,
        stripUnknown: true
      });

      if (error) {
        reply.code(400).send({
          error: 'Validation Error',
          details: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message
          }))
        });
        return;
      }

      request.body = value;
    } catch (err) {
      reply.code(500).send({ error: 'Validation processing error' });
    }
  };
};

module.exports = { schemas, validate };
```

#### SQL Injection Prevention

```javascript
// utils/sanitization.js
const mongoSanitize = require('express-mongo-sanitize');

const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    // Remove potential NoSQL injection patterns
    return input.replace(/[${}]/g, '');
  }
  
  if (typeof input === 'object' && input !== null) {
    return mongoSanitize.sanitize(input);
  }
  
  return input;
};

const sanitizeQuery = (query) => {
  const sanitized = {};
  
  for (const [key, value] of Object.entries(query)) {
    // Whitelist allowed query parameters
    if (['page', 'limit', 'sort', 'filter'].includes(key)) {
      sanitized[key] = sanitizeInput(value);
    }
  }
  
  return sanitized;
};

module.exports = { sanitizeInput, sanitizeQuery };
```

### 7.1.4 Security Headers

Essential security headers for protection against common attacks.

```javascript
// plugins/securityHeaders.js
const helmet = require('@fastify/helmet');

const securityHeadersConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", process.env.API_BASE_URL],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
};

// Custom security headers middleware
const customSecurityHeaders = async (request, reply) => {
  reply.header('X-Request-ID', request.id);
  reply.header('X-API-Version', process.env.API_VERSION || '1.0.0');
  reply.header('X-Tenant-Isolation', 'enabled');
  
  // Remove server information
  reply.removeHeader('X-Powered-By');
  reply.removeHeader('Server');
};

module.exports = { securityHeadersConfig, customSecurityHeaders };
```

## 7.2 Performance Optimization

### 7.2.1 Caching Strategies

Multi-level caching for optimal performance.

#### Redis Caching Layer

```javascript
// services/cacheService.js
const Redis = require('ioredis');

class CacheService {
  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });
  }

  async get(key) {
    try {
      const value = await this.redis.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = 3600) {
    try {
      await this.redis.setex(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      console.error('Cache set error:', error);
      return false;
    }
  }

  async del(key) {
    try {
      await this.redis.del(key);
      return true;
    } catch (error) {
      console.error('Cache delete error:', error);
      return false;
    }
  }

  async invalidatePattern(pattern) {
    try {
      const keys = await this.redis.keys(pattern);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
      return true;
    } catch (error) {
      console.error('Cache invalidation error:', error);
      return false;
    }
  }
}

module.exports = new CacheService();
```

#### JWT Token Caching

```javascript
// middleware/jwtCache.js
const cacheService = require('../services/cacheService');

const jwtCache = async (request, reply) => {
  const token = extractToken(request.headers.authorization);
  if (!token) return;

  const cacheKey = `jwt:${token}`;
  const cachedPayload = await cacheService.get(cacheKey);

  if (cachedPayload) {
    request.user = cachedPayload;
    return;
  }

  // If not cached, validate and cache
  try {
    const payload = await verifyJWT(token);
    await cacheService.set(cacheKey, payload, 300); // 5 minutes
    request.user = payload;
  } catch (error) {
    reply.code(401).send({ error: 'Invalid token' });
  }
};

module.exports = jwtCache;
```

#### Permission Caching

```javascript
// services/permissionCache.js
class PermissionCache {
  constructor(cacheService) {
    this.cache = cacheService;
    this.ttl = 600; // 10 minutes
  }

  async getUserPermissions(userId, tenantId) {
    const cacheKey = `permissions:${tenantId}:${userId}`;
    let permissions = await this.cache.get(cacheKey);

    if (!permissions) {
      permissions = await this.fetchUserPermissions(userId, tenantId);
      await this.cache.set(cacheKey, permissions, this.ttl);
    }

    return permissions;
  }

  async invalidateUserPermissions(userId, tenantId) {
    const cacheKey = `permissions:${tenantId}:${userId}`;
    await this.cache.del(cacheKey);
  }

  async invalidateTenantPermissions(tenantId) {
    const pattern = `permissions:${tenantId}:*`;
    await this.cache.invalidatePattern(pattern);
  }

  async fetchUserPermissions(userId, tenantId) {
    // Fetch from database
    const user = await db.collection('users').findOne({ 
      userId, 
      tenantId 
    });

    if (!user) return [];

    const roles = await db.collection('roles').find({
      _id: { $in: user.roleIds },
      tenantId
    }).toArray();

    const permissions = roles.reduce((acc, role) => {
      return [...acc, ...role.permissions];
    }, []);

    return [...new Set(permissions)]; // Remove duplicates
  }
}

module.exports = PermissionCache;
```

### 7.2.2 Connection Pooling

Efficient database connection management.

```javascript
// config/database.js
const { MongoClient } = require('mongodb');

class DatabaseManager {
  constructor() {
    this.client = null;
    this.db = null;
  }

  async connect() {
    const options = {
      maxPoolSize: 50, // Maximum connections
      minPoolSize: 5,  // Minimum connections
      maxIdleTimeMS: 30000, // Close connections after 30s of inactivity
      serverSelectionTimeoutMS: 5000, // How long to try selecting a server
      socketTimeoutMS: 45000, // How long a send or receive on a socket can take
      bufferMaxEntries: 0, // Disable mongoose buffering
      bufferCommands: false, // Disable mongoose buffering
      useNewUrlParser: true,
      useUnifiedTopology: true
    };

    this.client = new MongoClient(process.env.MONGODB_URI, options);
    await this.client.connect();
    this.db = this.client.db(process.env.MONGODB_DATABASE);
    
    console.log('Connected to MongoDB with connection pooling');
  }

  getDb() {
    if (!this.db) {
      throw new Error('Database not connected');
    }
    return this.db;
  }

  async close() {
    if (this.client) {
      await this.client.close();
    }
  }

  // Health check
  async ping() {
    try {
      await this.db.admin().ping();
      return true;
    } catch (error) {
      console.error('Database ping failed:', error);
      return false;
    }
  }
}

module.exports = new DatabaseManager();
```

### 7.2.3 Circuit Breaker Pattern

Prevent cascading failures in external service calls.

```javascript
// utils/circuitBreaker.js
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000; // 1 minute
    this.monitoringPeriod = options.monitoringPeriod || 10000; // 10 seconds
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.successCount = 0;
  }

  async execute(operation) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime >= this.resetTimeout) {
        this.state = 'HALF_OPEN';
        this.successCount = 0;
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failureCount = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= 3) { // Require 3 successes to close
        this.state = 'CLOSED';
      }
    }
  }

  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  getState() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      lastFailureTime: this.lastFailureTime
    };
  }
}

// Usage example for external API calls
const cognitoCircuitBreaker = new CircuitBreaker({
  failureThreshold: 3,
  resetTimeout: 30000
});

const validateTokenWithCircuitBreaker = async (token) => {
  return await cognitoCircuitBreaker.execute(async () => {
    return await validateTokenWithCognito(token);
  });
};

module.exports = CircuitBreaker;
```

### 7.2.4 Performance Monitoring

Real-time performance tracking and metrics.

```javascript
// middleware/performanceMonitoring.js
const performanceMonitoring = async (request, reply) => {
  const startTime = process.hrtime.bigint();
  
  reply.addHook('onSend', async (request, reply, payload) => {
    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    // Add performance headers
    reply.header('X-Response-Time', `${duration}ms`);
    
    // Log performance metrics
    const metrics = {
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      duration,
      tenantId: request.user?.tenantId,
      userId: request.user?.userId,
      timestamp: new Date().toISOString()
    };
    
    // Send to monitoring service
    await logPerformanceMetrics(metrics);
    
    return payload;
  });
};

const logPerformanceMetrics = async (metrics) => {
  try {
    // Log to database for analysis
    await db.collection('performance_metrics').insertOne(metrics);
    
    // Send to external monitoring (DataDog, New Relic, etc.)
    if (process.env.MONITORING_ENABLED === 'true') {
      await sendToMonitoringService(metrics);
    }
    
    // Alert on slow requests
    if (metrics.duration > 5000) { // 5 seconds
      await alertSlowRequest(metrics);
    }
  } catch (error) {
    console.error('Failed to log performance metrics:', error);
  }
};

module.exports = performanceMonitoring;
```

## 7.3 Error Handling

### 7.3.1 Standardized Error Responses

Consistent error response format across the API.

```javascript
// utils/errorHandler.js
class APIError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

class ValidationError extends APIError {
  constructor(message, details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

class AuthenticationError extends APIError {
  constructor(message = 'Authentication failed') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

class AuthorizationError extends APIError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

class NotFoundError extends APIError {
  constructor(resource = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND');
  }
}

class ConflictError extends APIError {
  constructor(message = 'Resource conflict') {
    super(message, 409, 'CONFLICT');
  }
}

class RateLimitError extends APIError {
  constructor(retryAfter = 60) {
    super('Rate limit exceeded', 429, 'RATE_LIMIT_EXCEEDED', { retryAfter });
  }
}

// Global error handler
const errorHandler = (error, request, reply) => {
  // Log error
  const errorLog = {
    error: {
      message: error.message,
      stack: error.stack,
      code: error.code || 'UNKNOWN_ERROR'
    },
    request: {
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body,
      user: request.user
    },
    timestamp: new Date().toISOString()
  };
  
  console.error('API Error:', errorLog);
  
  // Send error to monitoring service
  if (process.env.ERROR_TRACKING_ENABLED === 'true') {
    sendErrorToTracking(errorLog);
  }
  
  // Determine response
  if (error instanceof APIError) {
    reply.code(error.statusCode).send({
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
        timestamp: error.timestamp,
        requestId: request.id
      }
    });
  } else {
    // Unknown error - don't expose internal details
    reply.code(500).send({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An internal error occurred',
        timestamp: new Date().toISOString(),
        requestId: request.id
      }
    });
  }
};

module.exports = {
  APIError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  errorHandler
};
```

### 7.3.2 Error Logging and Tracking

Comprehensive error logging for debugging and monitoring.

```javascript
// services/errorTrackingService.js
const winston = require('winston');

class ErrorTrackingService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'api-gateway' },
      transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    });
  }

  async logError(error, context = {}) {
    const errorData = {
      message: error.message,
      stack: error.stack,
      code: error.code,
      statusCode: error.statusCode,
      context,
      timestamp: new Date().toISOString()
    };

    this.logger.error('API Error', errorData);

    // Store in database for analysis
    try {
      await db.collection('error_logs').insertOne({
        ...errorData,
        severity: this.getSeverity(error.statusCode),
        resolved: false
      });
    } catch (dbError) {
      console.error('Failed to store error in database:', dbError);
    }

    // Send to external error tracking service
    if (process.env.SENTRY_DSN) {
      await this.sendToSentry(error, context);
    }
  }

  getSeverity(statusCode) {
    if (statusCode >= 500) return 'critical';
    if (statusCode >= 400) return 'warning';
    return 'info';
  }

  async sendToSentry(error, context) {
    // Implementation for Sentry or other error tracking service
    try {
      const Sentry = require('@sentry/node');
      Sentry.withScope((scope) => {
        scope.setContext('request', context);
        Sentry.captureException(error);
      });
    } catch (sentryError) {
      console.error('Failed to send error to Sentry:', sentryError);
    }
  }

  async getErrorStats(tenantId, timeRange = '24h') {
    const startTime = new Date();
    startTime.setHours(startTime.getHours() - (timeRange === '24h' ? 24 : 1));

    const stats = await db.collection('error_logs').aggregate([
      {
        $match: {
          'context.tenantId': tenantId,
          timestamp: { $gte: startTime.toISOString() }
        }
      },
      {
        $group: {
          _id: '$code',
          count: { $sum: 1 },
          severity: { $first: '$severity' }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]).toArray();

    return stats;
  }
}

module.exports = new ErrorTrackingService();
```

### 7.3.3 Graceful Degradation

Handling service failures gracefully to maintain system availability.

```javascript
// services/gracefulDegradation.js
class GracefulDegradationService {
  constructor() {
    this.fallbackStrategies = new Map();
    this.serviceHealth = new Map();
  }

  registerFallback(serviceName, fallbackFunction) {
    this.fallbackStrategies.set(serviceName, fallbackFunction);
  }

  async executeWithFallback(serviceName, primaryFunction, context = {}) {
    try {
      // Try primary function
      const result = await primaryFunction();
      this.markServiceHealthy(serviceName);
      return result;
    } catch (error) {
      this.markServiceUnhealthy(serviceName, error);
      
      // Try fallback
      const fallback = this.fallbackStrategies.get(serviceName);
      if (fallback) {
        try {
          return await fallback(context);
        } catch (fallbackError) {
          console.error(`Fallback failed for ${serviceName}:`, fallbackError);
          throw error; // Throw original error
        }
      }
      
      throw error;
    }
  }

  markServiceHealthy(serviceName) {
    this.serviceHealth.set(serviceName, {
      status: 'healthy',
      lastCheck: new Date(),
      consecutiveFailures: 0
    });
  }

  markServiceUnhealthy(serviceName, error) {
    const current = this.serviceHealth.get(serviceName) || { consecutiveFailures: 0 };
    this.serviceHealth.set(serviceName, {
      status: 'unhealthy',
      lastCheck: new Date(),
      lastError: error.message,
      consecutiveFailures: current.consecutiveFailures + 1
    });
  }

  getServiceHealth() {
    return Object.fromEntries(this.serviceHealth);
  }
}

// Fallback implementations
const authFallback = async (context) => {
  // Return cached user data or guest permissions
  return {
    userId: 'guest',
    tenantId: context.tenantId || 'default',
    roles: ['guest'],
    permissions: ['read:public']
  };
};

const permissionFallback = async (context) => {
  // Allow basic read operations when permission service is down
  const { action, resource } = context;
  
  if (action === 'read' && ['public', 'profile'].includes(resource)) {
    return true;
  }
  
  return false;
};

// Setup fallbacks
const degradationService = new GracefulDegradationService();
degradationService.registerFallback('auth', authFallback);
degradationService.registerFallback('permissions', permissionFallback);

module.exports = degradationService;
```

#### Health Check Implementation

```javascript
// routes/health.js
const healthCheck = async (request, reply) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.API_VERSION || '1.0.0',
    services: {}
  };

  // Check database
  try {
    await db.admin().ping();
    health.services.database = { status: 'healthy' };
  } catch (error) {
    health.services.database = { 
      status: 'unhealthy', 
      error: error.message 
    };
    health.status = 'degraded';
  }

  // Check Redis
  try {
    await redis.ping();
    health.services.cache = { status: 'healthy' };
  } catch (error) {
    health.services.cache = { 
      status: 'unhealthy', 
      error: error.message 
    };
    health.status = 'degraded';
  }

  // Check AWS Cognito
  try {
    await cognitoClient.describeUserPool({ UserPoolId: process.env.COGNITO_USER_POOL_ID }).promise();
    health.services.cognito = { status: 'healthy' };
  } catch (error) {
    health.services.cognito = { 
      status: 'unhealthy', 
      error: error.message 
    };
    health.status = 'degraded';
  }

  // Add service degradation status
  health.degradation = degradationService.getServiceHealth();

  const statusCode = health.status === 'healthy' ? 200 : 503;
  reply.code(statusCode).send(health);
};

module.exports = { healthCheck };
```

This comprehensive Security & Performance documentation covers all the essential aspects needed for a production-ready Multi-Tenant API Gateway, including rate limiting, CORS configuration, input validation, caching strategies, connection pooling, circuit breaker patterns, performance monitoring, standardized error handling, and graceful degradation mechanisms. 