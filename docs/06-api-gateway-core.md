# API Gateway Core (Epic 4)

## 6.1 Request Routing

### 6.1.1 Route Configuration

The API Gateway implements a flexible routing system that supports dynamic route configuration, service discovery, and load balancing.

#### Route Configuration Schema

```typescript
// src/models/route.ts
export interface RouteConfig {
  _id: ObjectId;
  tenantId: string;
  path: string;           // Route pattern (e.g., "/api/v1/users/*")
  method: string[];       // HTTP methods ["GET", "POST", "PUT", "DELETE"]
  target: {
    service: string;      // Target service name
    url: string;          // Target URL pattern
    timeout: number;      // Request timeout in ms
    retries: number;      // Number of retries
  };
  middleware: string[];   // Middleware to apply
  authentication: {
    required: boolean;
    permissions: string[];
  };
  rateLimit: {
    enabled: boolean;
    requests: number;     // Requests per window
    window: number;       // Window in seconds
    skipSuccessfulRequests: boolean;
  };
  caching: {
    enabled: boolean;
    ttl: number;          // Cache TTL in seconds
    varyBy: string[];     // Cache key variations
  };
  transformation: {
    request?: {
      headers?: Record<string, string>;
      body?: any;
    };
    response?: {
      headers?: Record<string, string>;
      body?: any;
    };
  };
  isActive: boolean;
  priority: number;       // Route matching priority
  metadata: {
    description?: string;
    tags?: string[];
    version?: string;
    createdBy: ObjectId;
    updatedBy?: ObjectId;
  };
  createdAt: Date;
  updatedAt: Date;
}
```

#### Route Matching Engine

```typescript
// src/services/routeMatchingService.ts
export class RouteMatchingService {
  private routes: Map<string, RouteConfig[]> = new Map();
  private db: Db;

  constructor(db: Db) {
    this.db = db;
    this.loadRoutes();
  }

  async loadRoutes(): Promise<void> {
    const routes = await this.db.collection('routes').find({
      isActive: true
    }).sort({ priority: -1 }).toArray();

    // Group routes by tenant for faster lookup
    this.routes.clear();
    routes.forEach(route => {
      if (!this.routes.has(route.tenantId)) {
        this.routes.set(route.tenantId, []);
      }
      this.routes.get(route.tenantId)!.push(route);
    });
  }

  findMatchingRoute(
    tenantId: string,
    method: string,
    path: string
  ): RouteConfig | null {
    const tenantRoutes = this.routes.get(tenantId) || [];
    
    for (const route of tenantRoutes) {
      if (this.matchesRoute(route, method, path)) {
        return route;
      }
    }
    
    return null;
  }

  private matchesRoute(route: RouteConfig, method: string, path: string): boolean {
    // Check HTTP method
    if (!route.method.includes(method.toUpperCase())) {
      return false;
    }

    // Check path pattern
    return this.matchesPath(route.path, path);
  }

  private matchesPath(pattern: string, path: string): boolean {
    // Convert route pattern to regex
    const regexPattern = pattern
      .replace(/\*/g, '.*')           // * matches any characters
      .replace(/:\w+/g, '[^/]+')      // :param matches path segments
      .replace(/\//g, '\\/');         // Escape forward slashes

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(path);
  }

  extractPathParams(pattern: string, path: string): Record<string, string> {
    const params: Record<string, string> = {};
    const patternParts = pattern.split('/');
    const pathParts = path.split('/');

    if (patternParts.length !== pathParts.length) {
      return params;
    }

    patternParts.forEach((part, index) => {
      if (part.startsWith(':')) {
        const paramName = part.substring(1);
        params[paramName] = pathParts[index];
      }
    });

    return params;
  }

  async reloadRoutes(): Promise<void> {
    await this.loadRoutes();
  }

  async addRoute(route: RouteConfig): Promise<void> {
    await this.db.collection('routes').insertOne(route);
    await this.reloadRoutes();
  }

  async updateRoute(routeId: string, updates: Partial<RouteConfig>): Promise<void> {
    await this.db.collection('routes').updateOne(
      { _id: new ObjectId(routeId) },
      { $set: { ...updates, updatedAt: new Date() } }
    );
    await this.reloadRoutes();
  }

  async deleteRoute(routeId: string): Promise<void> {
    await this.db.collection('routes').updateOne(
      { _id: new ObjectId(routeId) },
      { $set: { isActive: false, updatedAt: new Date() } }
    );
    await this.reloadRoutes();
  }
}
```

### 6.1.2 Service Discovery

```typescript
// src/services/serviceDiscoveryService.ts
export interface ServiceEndpoint {
  id: string;
  url: string;
  health: 'healthy' | 'unhealthy' | 'unknown';
  weight: number;
  lastHealthCheck: Date;
  metadata: Record<string, any>;
}

export interface ServiceConfig {
  name: string;
  endpoints: ServiceEndpoint[];
  healthCheck: {
    path: string;
    interval: number;
    timeout: number;
    retries: number;
  };
  loadBalancing: {
    strategy: 'round-robin' | 'weighted' | 'least-connections' | 'random';
    stickySession: boolean;
  };
}

export class ServiceDiscoveryService {
  private services: Map<string, ServiceConfig> = new Map();
  private currentEndpoints: Map<string, number> = new Map(); // For round-robin
  private db: Db;
  private healthCheckInterval: NodeJS.Timeout;

  constructor(db: Db) {
    this.db = db;
    this.loadServices();
    this.startHealthChecks();
  }

  async loadServices(): Promise<void> {
    const services = await this.db.collection('services').find({
      isActive: true
    }).toArray();

    this.services.clear();
    services.forEach(service => {
      this.services.set(service.name, service);
      this.currentEndpoints.set(service.name, 0);
    });
  }

  getServiceEndpoint(serviceName: string, sessionId?: string): ServiceEndpoint | null {
    const service = this.services.get(serviceName);
    if (!service) {
      return null;
    }

    const healthyEndpoints = service.endpoints.filter(
      endpoint => endpoint.health === 'healthy'
    );

    if (healthyEndpoints.length === 0) {
      return null;
    }

    switch (service.loadBalancing.strategy) {
      case 'round-robin':
        return this.roundRobinSelection(serviceName, healthyEndpoints);
      
      case 'weighted':
        return this.weightedSelection(healthyEndpoints);
      
      case 'least-connections':
        return this.leastConnectionsSelection(healthyEndpoints);
      
      case 'random':
        return this.randomSelection(healthyEndpoints);
      
      default:
        return healthyEndpoints[0];
    }
  }

  private roundRobinSelection(serviceName: string, endpoints: ServiceEndpoint[]): ServiceEndpoint {
    const currentIndex = this.currentEndpoints.get(serviceName) || 0;
    const nextIndex = (currentIndex + 1) % endpoints.length;
    this.currentEndpoints.set(serviceName, nextIndex);
    return endpoints[currentIndex];
  }

  private weightedSelection(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    const totalWeight = endpoints.reduce((sum, endpoint) => sum + endpoint.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const endpoint of endpoints) {
      random -= endpoint.weight;
      if (random <= 0) {
        return endpoint;
      }
    }
    
    return endpoints[0];
  }

  private leastConnectionsSelection(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    // This would require tracking active connections per endpoint
    // For now, return the first endpoint
    return endpoints[0];
  }

  private randomSelection(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    const randomIndex = Math.floor(Math.random() * endpoints.length);
    return endpoints[randomIndex];
  }

  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthChecks();
    }, 30000); // Check every 30 seconds
  }

  private async performHealthChecks(): Promise<void> {
    for (const [serviceName, service] of this.services) {
      for (const endpoint of service.endpoints) {
        try {
          const healthUrl = `${endpoint.url}${service.healthCheck.path}`;
          const response = await fetch(healthUrl, {
            method: 'GET',
            timeout: service.healthCheck.timeout
          });

          endpoint.health = response.ok ? 'healthy' : 'unhealthy';
          endpoint.lastHealthCheck = new Date();
        } catch (error) {
          endpoint.health = 'unhealthy';
          endpoint.lastHealthCheck = new Date();
        }
      }

      // Update service in database
      await this.db.collection('services').updateOne(
        { name: serviceName },
        { $set: { endpoints: service.endpoints, updatedAt: new Date() } }
      );
    }
  }

  async registerService(serviceConfig: ServiceConfig): Promise<void> {
    await this.db.collection('services').insertOne({
      ...serviceConfig,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    await this.loadServices();
  }

  async updateService(serviceName: string, updates: Partial<ServiceConfig>): Promise<void> {
    await this.db.collection('services').updateOne(
      { name: serviceName },
      { $set: { ...updates, updatedAt: new Date() } }
    );
    await this.loadServices();
  }

  async deregisterService(serviceName: string): Promise<void> {
    await this.db.collection('services').updateOne(
      { name: serviceName },
      { $set: { isActive: false, updatedAt: new Date() } }
    );
    this.services.delete(serviceName);
    this.currentEndpoints.delete(serviceName);
  }

  getServiceHealth(serviceName: string): {
    service: string;
    totalEndpoints: number;
    healthyEndpoints: number;
    endpoints: ServiceEndpoint[];
  } | null {
    const service = this.services.get(serviceName);
    if (!service) {
      return null;
    }

    const healthyCount = service.endpoints.filter(
      endpoint => endpoint.health === 'healthy'
    ).length;

    return {
      service: serviceName,
      totalEndpoints: service.endpoints.length,
      healthyEndpoints: healthyCount,
      endpoints: service.endpoints
    };
  }

  destroy(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
  }
}
```

### 6.1.3 Load Balancing Strategies

```typescript
// src/services/loadBalancerService.ts
export class LoadBalancerService {
  private connectionCounts: Map<string, number> = new Map();
  private stickySessionMap: Map<string, string> = new Map();

  selectEndpoint(
    endpoints: ServiceEndpoint[],
    strategy: string,
    sessionId?: string
  ): ServiceEndpoint | null {
    if (endpoints.length === 0) {
      return null;
    }

    // Check for sticky session
    if (sessionId && this.stickySessionMap.has(sessionId)) {
      const stickyEndpointId = this.stickySessionMap.get(sessionId)!;
      const stickyEndpoint = endpoints.find(ep => ep.id === stickyEndpointId);
      if (stickyEndpoint && stickyEndpoint.health === 'healthy') {
        return stickyEndpoint;
      }
    }

    let selectedEndpoint: ServiceEndpoint;

    switch (strategy) {
      case 'round-robin':
        selectedEndpoint = this.roundRobin(endpoints);
        break;
      
      case 'weighted':
        selectedEndpoint = this.weighted(endpoints);
        break;
      
      case 'least-connections':
        selectedEndpoint = this.leastConnections(endpoints);
        break;
      
      case 'ip-hash':
        selectedEndpoint = this.ipHash(endpoints, sessionId || '');
        break;
      
      case 'random':
      default:
        selectedEndpoint = this.random(endpoints);
        break;
    }

    // Set sticky session if provided
    if (sessionId) {
      this.stickySessionMap.set(sessionId, selectedEndpoint.id);
    }

    return selectedEndpoint;
  }

  private roundRobin(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    // Implementation would track current index per service
    return endpoints[0];
  }

  private weighted(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    const totalWeight = endpoints.reduce((sum, ep) => sum + ep.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const endpoint of endpoints) {
      random -= endpoint.weight;
      if (random <= 0) {
        return endpoint;
      }
    }
    
    return endpoints[0];
  }

  private leastConnections(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    let minConnections = Infinity;
    let selectedEndpoint = endpoints[0];
    
    for (const endpoint of endpoints) {
      const connections = this.connectionCounts.get(endpoint.id) || 0;
      if (connections < minConnections) {
        minConnections = connections;
        selectedEndpoint = endpoint;
      }
    }
    
    return selectedEndpoint;
  }

  private ipHash(endpoints: ServiceEndpoint[], clientId: string): ServiceEndpoint {
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < clientId.length; i++) {
      const char = clientId.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    const index = Math.abs(hash) % endpoints.length;
    return endpoints[index];
  }

  private random(endpoints: ServiceEndpoint[]): ServiceEndpoint {
    const randomIndex = Math.floor(Math.random() * endpoints.length);
    return endpoints[randomIndex];
  }

  incrementConnection(endpointId: string): void {
    const current = this.connectionCounts.get(endpointId) || 0;
    this.connectionCounts.set(endpointId, current + 1);
  }

  decrementConnection(endpointId: string): void {
    const current = this.connectionCounts.get(endpointId) || 0;
    this.connectionCounts.set(endpointId, Math.max(0, current - 1));
  }

  clearStickySession(sessionId: string): void {
    this.stickySessionMap.delete(sessionId);
  }

  getConnectionStats(): Record<string, number> {
    return Object.fromEntries(this.connectionCounts);
  }
}
```

## 6.2 Middleware Pipeline

### 6.2.1 Authentication Middleware

```typescript
// src/middleware/authenticationMiddleware.ts
export const authenticationMiddleware = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  try {
    // Skip authentication for health checks and public endpoints
    if (isPublicEndpoint(request.url)) {
      return;
    }

    const authHeader = request.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      });
    }

    const token = authHeader.substring(7);
    
    // Validate JWT token
    const decoded = await validateJWTToken(token);
    
    // Extract user information
    request.user = {
      userId: decoded.sub,
      email: decoded.email,
      tenantId: decoded.tenantId,
      roles: decoded.roles || [],
      permissions: decoded.permissions || []
    };

    // Log authentication event
    await logAuthenticationEvent(request, 'authenticated');

  } catch (error) {
    request.log.error('Authentication failed:', error);
    
    await logAuthenticationEvent(request, 'authentication_failed', {
      error: error.message
    });
    
    return reply.code(401).send({
      error: 'Unauthorized',
      message: 'Invalid or expired token'
    });
  }
};

function isPublicEndpoint(url: string): boolean {
  const publicPaths = [
    '/health',
    '/metrics',
    '/auth/login',
    '/auth/register',
    '/docs'
  ];
  
  return publicPaths.some(path => url.startsWith(path));
}

async function validateJWTToken(token: string): Promise<any> {
  // Implementation would validate against Cognito
  // This is a simplified version
  const jwt = require('jsonwebtoken');
  return jwt.verify(token, process.env.JWT_SECRET);
}

async function logAuthenticationEvent(
  request: FastifyRequest,
  event: string,
  details?: any
): Promise<void> {
  const auditLog = {
    event,
    ip: request.ip,
    userAgent: request.headers['user-agent'],
    url: request.url,
    method: request.method,
    timestamp: new Date(),
    details
  };

  // Log to audit system
  request.log.info('Authentication event', auditLog);
}
```

### 6.2.2 Authorization Middleware

```typescript
// src/middleware/authorizationMiddleware.ts
export const authorizationMiddleware = (requiredPermissions: string[]) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user;
      
      if (!user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Check if user has required permissions
      const hasPermission = await checkUserPermissions(
        user.userId,
        user.tenantId,
        requiredPermissions,
        request
      );

      if (!hasPermission) {
        await logAuthorizationEvent(request, 'access_denied', {
          requiredPermissions,
          userPermissions: user.permissions
        });

        return reply.code(403).send({
          error: 'Forbidden',
          message: 'Insufficient permissions'
        });
      }

      await logAuthorizationEvent(request, 'access_granted', {
        requiredPermissions
      });

    } catch (error) {
      request.log.error('Authorization failed:', error);
      
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Authorization check failed'
      });
    }
  };
};

async function checkUserPermissions(
  userId: string,
  tenantId: string,
  requiredPermissions: string[],
  request: FastifyRequest
): Promise<boolean> {
  const permissionService = new PermissionCheckService(request.server.mongo.db);
  
  return permissionService.checkUserAnyPermission(
    userId,
    tenantId,
    requiredPermissions,
    {
      user: request.user,
      params: request.params,
      body: request.body,
      query: request.query
    }
  );
}

async function logAuthorizationEvent(
  request: FastifyRequest,
  event: string,
  details?: any
): Promise<void> {
  const auditLog = {
    event,
    userId: request.user?.userId,
    tenantId: request.user?.tenantId,
    ip: request.ip,
    userAgent: request.headers['user-agent'],
    url: request.url,
    method: request.method,
    timestamp: new Date(),
    details
  };

  request.log.info('Authorization event', auditLog);
}
```

### 6.2.3 Tenant Validation Middleware

```typescript
// src/middleware/tenantValidationMiddleware.ts
export const tenantValidationMiddleware = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  try {
    const user = request.user;
    
    if (!user || !user.tenantId) {
      return reply.code(400).send({
        error: 'Bad Request',
        message: 'Tenant information missing'
      });
    }

    // Validate tenant exists and is active
    const tenant = await validateTenant(user.tenantId, request.server.mongo.db);
    
    if (!tenant) {
      return reply.code(404).send({
        error: 'Not Found',
        message: 'Tenant not found'
      });
    }

    if (tenant.status !== 'active') {
      return reply.code(403).send({
        error: 'Forbidden',
        message: `Tenant is ${tenant.status}`
      });
    }

    // Check tenant limits
    const limits = await checkTenantLimits(user.tenantId, request.server.mongo.db);
    
    if (limits.exceeded) {
      return reply.code(429).send({
        error: 'Too Many Requests',
        message: 'Tenant limits exceeded',
        details: limits
      });
    }

    // Add tenant info to request
    request.tenant = tenant;

  } catch (error) {
    request.log.error('Tenant validation failed:', error);
    
    return reply.code(500).send({
      error: 'Internal Server Error',
      message: 'Tenant validation failed'
    });
  }
};

async function validateTenant(tenantId: string, db: Db): Promise<any> {
  return db.collection('tenants').findOne({
    tenantId,
    status: { $in: ['active', 'suspended'] }
  });
}

async function checkTenantLimits(tenantId: string, db: Db): Promise<{
  exceeded: boolean;
  limits: any;
  current: any;
}> {
  const tenant = await db.collection('tenants').findOne({ tenantId });
  
  if (!tenant) {
    return { exceeded: false, limits: {}, current: {} };
  }

  const currentMonth = new Date();
  currentMonth.setDate(1);
  currentMonth.setHours(0, 0, 0, 0);

  // Check API call limits
  const currentApiCalls = await db.collection('auditLogs').countDocuments({
    tenantId,
    event: 'api_request',
    timestamp: { $gte: currentMonth }
  });

  // Check user limits
  const currentUsers = await db.collection('users').countDocuments({
    tenantId,
    status: 'active'
  });

  const limits = {
    maxApiCalls: tenant.settings.billing.maxApiCalls,
    maxUsers: tenant.settings.maxUsers
  };

  const current = {
    apiCalls: currentApiCalls,
    users: currentUsers
  };

  const exceeded = (
    (limits.maxApiCalls > 0 && current.apiCalls >= limits.maxApiCalls) ||
    (limits.maxUsers > 0 && current.users >= limits.maxUsers)
  );

  return { exceeded, limits, current };
}
```

### 6.2.4 Request/Response Transformation

```typescript
// src/middleware/transformationMiddleware.ts
export interface TransformationConfig {
  request?: {
    headers?: Record<string, string>;
    body?: any;
    query?: Record<string, string>;
  };
  response?: {
    headers?: Record<string, string>;
    body?: any;
  };
}

export const requestTransformationMiddleware = (config: TransformationConfig) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      if (config.request) {
        // Transform headers
        if (config.request.headers) {
          Object.entries(config.request.headers).forEach(([key, value]) => {
            request.headers[key.toLowerCase()] = interpolateValue(value, request);
          });
        }

        // Transform query parameters
        if (config.request.query) {
          Object.entries(config.request.query).forEach(([key, value]) => {
            request.query[key] = interpolateValue(value, request);
          });
        }

        // Transform body
        if (config.request.body && request.body) {
          request.body = transformObject(config.request.body, request.body, request);
        }
      }
    } catch (error) {
      request.log.error('Request transformation failed:', error);
      
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Request transformation failed'
      });
    }
  };
};

export const responseTransformationMiddleware = (config: TransformationConfig) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      if (config.response) {
        // Transform response headers
        if (config.response.headers) {
          Object.entries(config.response.headers).forEach(([key, value]) => {
            reply.header(key, interpolateValue(value, request));
          });
        }

        // Response body transformation would be handled in the proxy response
      }
    } catch (error) {
      request.log.error('Response transformation failed:', error);
    }
  };
};

function interpolateValue(template: string, request: FastifyRequest): string {
  return template
    .replace(/\$\{user\.(\w+)\}/g, (_, prop) => request.user?.[prop] || '')
    .replace(/\$\{tenant\.(\w+)\}/g, (_, prop) => request.tenant?.[prop] || '')
    .replace(/\$\{header\.(\w+)\}/g, (_, header) => request.headers[header.toLowerCase()] || '')
    .replace(/\$\{query\.(\w+)\}/g, (_, param) => request.query[param] || '')
    .replace(/\$\{timestamp\}/g, new Date().toISOString())
    .replace(/\$\{requestId\}/g, request.id);
}

function transformObject(template: any, source: any, request: FastifyRequest): any {
  if (typeof template === 'string') {
    return interpolateValue(template, request);
  }
  
  if (Array.isArray(template)) {
    return template.map(item => transformObject(item, source, request));
  }
  
  if (typeof template === 'object' && template !== null) {
    const result: any = {};
    
    Object.entries(template).forEach(([key, value]) => {
      if (typeof value === 'string' && value.startsWith('$source.')) {
        const sourcePath = value.substring(8); // Remove '$source.'
        result[key] = getNestedProperty(source, sourcePath);
      } else {
        result[key] = transformObject(value, source, request);
      }
    });
    
    return result;
  }
  
  return template;
}

function getNestedProperty(obj: any, path: string): any {
  return path.split('.').reduce((current, prop) => current?.[prop], obj);
}
```

## 6.3 Proxy Implementation

### 6.3.1 Backend Service Integration

```typescript
// src/services/proxyService.ts
export class ProxyService {
  private serviceDiscovery: ServiceDiscoveryService;
  private loadBalancer: LoadBalancerService;
  private circuitBreaker: CircuitBreakerService;

  constructor(
    serviceDiscovery: ServiceDiscoveryService,
    loadBalancer: LoadBalancerService,
    circuitBreaker: CircuitBreakerService
  ) {
    this.serviceDiscovery = serviceDiscovery;
    this.loadBalancer = loadBalancer;
    this.circuitBreaker = circuitBreaker;
  }

  async proxyRequest(
    request: FastifyRequest,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    const startTime = Date.now();
    let selectedEndpoint: ServiceEndpoint | null = null;

    try {
      // Get service endpoint
      selectedEndpoint = this.serviceDiscovery.getServiceEndpoint(
        route.target.service,
        request.sessionId
      );

      if (!selectedEndpoint) {
        throw new Error(`No healthy endpoints available for service: ${route.target.service}`);
      }

      // Check circuit breaker
      if (this.circuitBreaker.isOpen(selectedEndpoint.id)) {
        throw new Error(`Circuit breaker is open for endpoint: ${selectedEndpoint.id}`);
      }

      // Increment connection count
      this.loadBalancer.incrementConnection(selectedEndpoint.id);

      // Build target URL
      const targetUrl = this.buildTargetUrl(selectedEndpoint, route, request);

      // Prepare request options
      const requestOptions = this.prepareRequestOptions(request, route);

      // Make the request
      const response = await this.makeRequest(targetUrl, requestOptions);

      // Handle successful response
      await this.handleSuccessfulResponse(response, reply, route);

      // Record success in circuit breaker
      this.circuitBreaker.recordSuccess(selectedEndpoint.id);

      // Log successful proxy
      await this.logProxyEvent(request, route, selectedEndpoint, {
        status: response.status,
        duration: Date.now() - startTime
      });

    } catch (error) {
      // Record failure in circuit breaker
      if (selectedEndpoint) {
        this.circuitBreaker.recordFailure(selectedEndpoint.id);
      }

      // Handle error response
      await this.handleErrorResponse(error, reply, route);

      // Log failed proxy
      await this.logProxyEvent(request, route, selectedEndpoint, {
        error: error.message,
        duration: Date.now() - startTime
      });

    } finally {
      // Decrement connection count
      if (selectedEndpoint) {
        this.loadBalancer.decrementConnection(selectedEndpoint.id);
      }
    }
  }

  private buildTargetUrl(
    endpoint: ServiceEndpoint,
    route: RouteConfig,
    request: FastifyRequest
  ): string {
    const baseUrl = endpoint.url.replace(/\/$/, ''); // Remove trailing slash
    const targetPath = route.target.url || request.url;
    
    // Replace path parameters
    let finalPath = targetPath;
    if (request.params) {
      Object.entries(request.params).forEach(([key, value]) => {
        finalPath = finalPath.replace(`:${key}`, encodeURIComponent(value as string));
      });
    }

    // Add query parameters
    const queryString = new URLSearchParams(request.query as any).toString();
    const separator = finalPath.includes('?') ? '&' : '?';
    
    return `${baseUrl}${finalPath}${queryString ? separator + queryString : ''}`;
  }

  private prepareRequestOptions(
    request: FastifyRequest,
    route: RouteConfig
  ): RequestInit {
    const headers: Record<string, string> = {};

    // Copy relevant headers
    const allowedHeaders = [
      'content-type',
      'accept',
      'user-agent',
      'x-forwarded-for',
      'x-real-ip'
    ];

    allowedHeaders.forEach(header => {
      if (request.headers[header]) {
        headers[header] = request.headers[header] as string;
      }
    });

    // Add custom headers from route configuration
    if (route.transformation?.request?.headers) {
      Object.assign(headers, route.transformation.request.headers);
    }

    // Add tenant and user context headers
    if (request.user) {
      headers['x-tenant-id'] = request.user.tenantId;
      headers['x-user-id'] = request.user.userId;
      headers['x-user-roles'] = JSON.stringify(request.user.roles);
    }

    // Add request ID for tracing
    headers['x-request-id'] = request.id;

    const options: RequestInit = {
      method: request.method,
      headers,
      timeout: route.target.timeout || 30000
    };

    // Add body for non-GET requests
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      if (request.body) {
        options.body = JSON.stringify(request.body);
        headers['content-type'] = 'application/json';
      }
    }

    return options;
  }

  private async makeRequest(url: string, options: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeout as number);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  private async handleSuccessfulResponse(
    response: Response,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    // Set response status
    reply.code(response.status);

    // Copy response headers
    response.headers.forEach((value, key) => {
      // Skip certain headers that shouldn't be forwarded
      if (!['content-encoding', 'transfer-encoding', 'connection'].includes(key.toLowerCase())) {
        reply.header(key, value);
      }
    });

    // Apply response transformations
    if (route.transformation?.response?.headers) {
      Object.entries(route.transformation.response.headers).forEach(([key, value]) => {
        reply.header(key, value);
      });
    }

    // Handle response body
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('application/json')) {
      const jsonData = await response.json();
      
      // Apply body transformation if configured
      if (route.transformation?.response?.body) {
        const transformedData = this.transformResponseBody(
          jsonData,
          route.transformation.response.body
        );
        reply.send(transformedData);
      } else {
        reply.send(jsonData);
      }
    } else {
      // Stream non-JSON responses
      const buffer = await response.arrayBuffer();
      reply.send(Buffer.from(buffer));
    }
  }

  private async handleErrorResponse(
    error: Error,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    let statusCode = 500;
    let message = 'Internal Server Error';

    if (error.message.includes('No healthy endpoints')) {
      statusCode = 503;
      message = 'Service Unavailable';
    } else if (error.message.includes('Circuit breaker is open')) {
      statusCode = 503;
      message = 'Service Temporarily Unavailable';
    } else if (error.message.includes('timeout')) {
      statusCode = 504;
      message = 'Gateway Timeout';
    }

    reply.code(statusCode).send({
      error: message,
      message: error.message,
      timestamp: new Date().toISOString(),
      requestId: reply.request.id
    });
  }

  private transformResponseBody(data: any, transformation: any): any {
    // Simple transformation logic
    // In a real implementation, this would be more sophisticated
    if (typeof transformation === 'object') {
      const result: any = {};
      
      Object.entries(transformation).forEach(([key, value]) => {
        if (typeof value === 'string' && value.startsWith('$data.')) {
          const dataPath = value.substring(6);
          result[key] = getNestedProperty(data, dataPath);
        } else {
          result[key] = value;
        }
      });
      
      return result;
    }
    
    return data;
  }

  private async logProxyEvent(
    request: FastifyRequest,
    route: RouteConfig,
    endpoint: ServiceEndpoint | null,
    details: any
  ): Promise<void> {
    const logData = {
      event: 'proxy_request',
      tenantId: request.user?.tenantId,
      userId: request.user?.userId,
      route: {
        path: route.path,
        service: route.target.service
      },
      endpoint: endpoint ? {
        id: endpoint.id,
        url: endpoint.url
      } : null,
      request: {
        method: request.method,
        url: request.url,
        ip: request.ip,
        userAgent: request.headers['user-agent']
      },
      timestamp: new Date(),
      ...details
    };

    request.log.info('Proxy event', logData);
  }
}

function getNestedProperty(obj: any, path: string): any {
  return path.split('.').reduce((current, prop) => current?.[prop], obj);
}
```

### 6.3.2 Request Forwarding

```typescript
// src/services/requestForwardingService.ts
export class RequestForwardingService {
  private retryConfig: {
    maxRetries: number;
    retryDelay: number;
    retryMultiplier: number;
  };

  constructor() {
    this.retryConfig = {
      maxRetries: 3,
      retryDelay: 1000,
      retryMultiplier: 2
    };
  }

  async forwardRequest(
    request: FastifyRequest,
    targetUrl: string,
    options: RequestInit,
    retries: number = 0
  ): Promise<Response> {
    try {
      const response = await fetch(targetUrl, options);
      
      // Check if response indicates a retryable error
      if (this.isRetryableError(response.status) && retries < this.retryConfig.maxRetries) {
        await this.delay(this.calculateRetryDelay(retries));
        return this.forwardRequest(request, targetUrl, options, retries + 1);
      }
      
      return response;
    } catch (error) {
      // Network errors are retryable
      if (retries < this.retryConfig.maxRetries) {
        await this.delay(this.calculateRetryDelay(retries));
        return this.forwardRequest(request, targetUrl, options, retries + 1);
      }
      
      throw error;
    }
  }

  private isRetryableError(statusCode: number): boolean {
    // Retry on server errors and rate limiting
    return statusCode >= 500 || statusCode === 429;
  }

  private calculateRetryDelay(retryCount: number): number {
    return this.retryConfig.retryDelay * Math.pow(this.retryConfig.retryMultiplier, retryCount);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async streamResponse(
    response: Response,
    reply: FastifyReply
  ): Promise<void> {
    if (!response.body) {
      return;
    }

    const reader = response.body.getReader();
    
    try {
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) {
          break;
        }
        
        reply.raw.write(value);
      }
      
      reply.raw.end();
    } catch (error) {
      reply.raw.destroy(error);
    } finally {
      reader.releaseLock();
    }
  }

  prepareHeaders(
    originalHeaders: Record<string, string | string[]>,
    additionalHeaders: Record<string, string> = {}
  ): Record<string, string> {
    const headers: Record<string, string> = {};
    
    // Copy safe headers
    const safeHeaders = [
      'accept',
      'accept-encoding',
      'accept-language',
      'cache-control',
      'content-type',
      'user-agent'
    ];
    
    safeHeaders.forEach(header => {
      const value = originalHeaders[header];
      if (value) {
        headers[header] = Array.isArray(value) ? value[0] : value;
      }
    });
    
    // Add additional headers
    Object.assign(headers, additionalHeaders);
    
    // Remove hop-by-hop headers
    const hopByHopHeaders = [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'transfer-encoding',
      'upgrade'
    ];
    
    hopByHopHeaders.forEach(header => {
      delete headers[header];
    });
    
    return headers;
  }
}
```

### 6.3.3 Response Handling

```typescript
// src/services/responseHandlingService.ts
export class ResponseHandlingService {
  async handleResponse(
    response: Response,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    try {
      // Set status code
      reply.code(response.status);
      
      // Handle headers
      this.copyResponseHeaders(response, reply);
      
      // Apply response transformations
      if (route.transformation?.response) {
        this.applyResponseTransformations(response, reply, route.transformation.response);
      }
      
      // Handle body based on content type
      await this.handleResponseBody(response, reply, route);
      
    } catch (error) {
      reply.log.error('Response handling failed:', error);
      
      if (!reply.sent) {
        reply.code(500).send({
          error: 'Internal Server Error',
          message: 'Response processing failed'
        });
      }
    }
  }

  private copyResponseHeaders(response: Response, reply: FastifyReply): void {
    const excludedHeaders = [
      'content-encoding',
      'content-length',
      'transfer-encoding',
      'connection',
      'keep-alive',
      'upgrade',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers'
    ];
    
    response.headers.forEach((value, key) => {
      if (!excludedHeaders.includes(key.toLowerCase())) {
        reply.header(key, value);
      }
    });
  }

  private applyResponseTransformations(
    response: Response,
    reply: FastifyReply,
    transformation: any
  ): void {
    if (transformation.headers) {
      Object.entries(transformation.headers).forEach(([key, value]) => {
        reply.header(key, value as string);
      });
    }
  }

  private async handleResponseBody(
    response: Response,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('application/json')) {
      await this.handleJsonResponse(response, reply, route);
    } else if (contentType.includes('text/')) {
      await this.handleTextResponse(response, reply);
    } else if (this.isStreamableContent(contentType)) {
      await this.handleStreamResponse(response, reply);
    } else {
      await this.handleBinaryResponse(response, reply);
    }
  }

  private async handleJsonResponse(
    response: Response,
    reply: FastifyReply,
    route: RouteConfig
  ): Promise<void> {
    try {
      const data = await response.json();
      
      // Apply body transformation if configured
      if (route.transformation?.response?.body) {
        const transformedData = this.transformJsonData(
          data,
          route.transformation.response.body
        );
        reply.send(transformedData);
      } else {
        reply.send(data);
      }
    } catch (error) {
      reply.log.error('JSON parsing failed:', error);
      reply.code(502).send({
        error: 'Bad Gateway',
        message: 'Invalid JSON response from upstream service'
      });
    }
  }

  private async handleTextResponse(
    response: Response,
    reply: FastifyReply
  ): Promise<void> {
    const text = await response.text();
    reply.type('text/plain').send(text);
  }

  private async handleStreamResponse(
    response: Response,
    reply: FastifyReply
  ): Promise<void> {
    if (!response.body) {
      reply.send('');
      return;
    }

    const reader = response.body.getReader();
    
    try {
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) {
          break;
        }
        
        reply.raw.write(value);
      }
      
      reply.raw.end();
    } catch (error) {
      reply.log.error('Stream handling failed:', error);
      reply.raw.destroy(error);
    } finally {
      reader.releaseLock();
    }
  }

  private async handleBinaryResponse(
    response: Response,
    reply: FastifyReply
  ): Promise<void> {
    const buffer = await response.arrayBuffer();
    reply.send(Buffer.from(buffer));
  }

  private isStreamableContent(contentType: string): boolean {
    const streamableTypes = [
      'application/octet-stream',
      'video/',
      'audio/',
      'image/',
      'application/pdf'
    ];
    
    return streamableTypes.some(type => contentType.includes(type));
  }

  private transformJsonData(data: any, transformation: any): any {
    if (typeof transformation === 'function') {
      return transformation(data);
    }
    
    if (typeof transformation === 'object') {
      return this.applyObjectTransformation(data, transformation);
    }
    
    return data;
  }

  private applyObjectTransformation(data: any, transformation: any): any {
    const result: any = {};
    
    Object.entries(transformation).forEach(([key, value]) => {
      if (typeof value === 'string') {
        if (value.startsWith('$data.')) {
          const path = value.substring(6);
          result[key] = this.getNestedValue(data, path);
        } else if (value.startsWith('$computed.')) {
          // Handle computed values
          result[key] = this.computeValue(value, data);
        } else {
          result[key] = value;
        }
      } else if (typeof value === 'object') {
        result[key] = this.applyObjectTransformation(data, value);
      } else {
        result[key] = value;
      }
    });
    
    return result;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, prop) => {
      return current && current[prop] !== undefined ? current[prop] : null;
    }, obj);
  }

  private computeValue(expression: string, data: any): any {
    // Simple computed value implementation
    // In production, this would be more sophisticated
    if (expression === '$computed.timestamp') {
      return new Date().toISOString();
    }
    
    if (expression === '$computed.count') {
      return Array.isArray(data) ? data.length : 1;
    }
    
    return null;
  }

  handleErrorResponse(
    error: Error,
    reply: FastifyReply,
    statusCode: number = 500
  ): void {
    const errorResponse = {
      error: this.getErrorName(statusCode),
      message: error.message,
      timestamp: new Date().toISOString(),
      requestId: reply.request.id
    };
    
    reply.code(statusCode).send(errorResponse);
  }

  private getErrorName(statusCode: number): string {
    const errorNames: Record<number, string> = {
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      429: 'Too Many Requests',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable',
      504: 'Gateway Timeout'
    };
    
    return errorNames[statusCode] || 'Unknown Error';
  }
}
```

## 6.4 Audit and Logging

### 6.4.1 Access Logging

```typescript
// src/services/accessLoggingService.ts
export interface AccessLogEntry {
  timestamp: Date;
  requestId: string;
  tenantId?: string;
  userId?: string;
  method: string;
  url: string;
  userAgent?: string;
  ip: string;
  statusCode: number;
  responseTime: number;
  requestSize: number;
  responseSize: number;
  referer?: string;
  route?: {
    path: string;
    service: string;
  };
  error?: string;
}

export class AccessLoggingService {
  private db: Db;
  private logBuffer: AccessLogEntry[] = [];
  private bufferSize = 100;
  private flushInterval = 5000; // 5 seconds

  constructor(db: Db) {
    this.db = db;
    this.startPeriodicFlush();
  }

  logAccess(entry: AccessLogEntry): void {
    this.logBuffer.push(entry);
    
    if (this.logBuffer.length >= this.bufferSize) {
      this.flushLogs();
    }
  }

  private async flushLogs(): Promise<void> {
    if (this.logBuffer.length === 0) {
      return;
    }

    const logsToFlush = [...this.logBuffer];
    this.logBuffer = [];

    try {
      await this.db.collection('accessLogs').insertMany(logsToFlush);
    } catch (error) {
      console.error('Failed to flush access logs:', error);
      // Re-add logs to buffer for retry
      this.logBuffer.unshift(...logsToFlush);
    }
  }

  private startPeriodicFlush(): void {
    setInterval(() => {
      this.flushLogs();
    }, this.flushInterval);
  }

  async getAccessLogs(filter: {
    tenantId?: string;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
    statusCode?: number;
    method?: string;
    page?: number;
    limit?: number;
  }): Promise<{
    logs: AccessLogEntry[];
    total: number;
    page: number;
    limit: number;
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.userId) {
      query.userId = filter.userId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }
    
    if (filter.statusCode) {
      query.statusCode = filter.statusCode;
    }
    
    if (filter.method) {
      query.method = filter.method.toUpperCase();
    }

    const page = filter.page || 1;
    const limit = filter.limit || 50;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.db.collection('accessLogs')
        .find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      this.db.collection('accessLogs').countDocuments(query)
    ]);

    return {
      logs,
      total,
      page,
      limit
    };
  }

  async getAccessStats(filter: {
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<{
    totalRequests: number;
    successfulRequests: number;
    errorRequests: number;
    averageResponseTime: number;
    requestsByMethod: Record<string, number>;
    requestsByStatus: Record<string, number>;
    topEndpoints: Array<{ endpoint: string; count: number }>;
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const pipeline = [
      { $match: query },
      {
        $group: {
          _id: null,
          totalRequests: { $sum: 1 },
          successfulRequests: {
            $sum: {
              $cond: [{ $lt: ['$statusCode', 400] }, 1, 0]
            }
          },
          errorRequests: {
            $sum: {
              $cond: [{ $gte: ['$statusCode', 400] }, 1, 0]
            }
          },
          averageResponseTime: { $avg: '$responseTime' },
          methods: { $push: '$method' },
          statuses: { $push: '$statusCode' },
          urls: { $push: '$url' }
        }
      }
    ];

    const [result] = await this.db.collection('accessLogs').aggregate(pipeline).toArray();
    
    if (!result) {
      return {
        totalRequests: 0,
        successfulRequests: 0,
        errorRequests: 0,
        averageResponseTime: 0,
        requestsByMethod: {},
        requestsByStatus: {},
        topEndpoints: []
      };
    }

    // Count by method
    const requestsByMethod: Record<string, number> = {};
    result.methods.forEach((method: string) => {
      requestsByMethod[method] = (requestsByMethod[method] || 0) + 1;
    });

    // Count by status
    const requestsByStatus: Record<string, number> = {};
    result.statuses.forEach((status: number) => {
      const statusRange = `${Math.floor(status / 100)}xx`;
      requestsByStatus[statusRange] = (requestsByStatus[statusRange] || 0) + 1;
    });

    // Top endpoints
    const endpointCounts: Record<string, number> = {};
    result.urls.forEach((url: string) => {
      endpointCounts[url] = (endpointCounts[url] || 0) + 1;
    });

    const topEndpoints = Object.entries(endpointCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([endpoint, count]) => ({ endpoint, count }));

    return {
      totalRequests: result.totalRequests,
      successfulRequests: result.successfulRequests,
      errorRequests: result.errorRequests,
      averageResponseTime: Math.round(result.averageResponseTime),
      requestsByMethod,
      requestsByStatus,
      topEndpoints
    };
  }
}
```

### 6.4.2 Security Event Logging

```typescript
// src/services/securityLoggingService.ts
export interface SecurityEvent {
  timestamp: Date;
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  tenantId?: string;
  userId?: string;
  ip: string;
  userAgent?: string;
  details: any;
  requestId?: string;
}

export class SecurityLoggingService {
  private db: Db;
  private alertThresholds: Record<string, number>;

  constructor(db: Db) {
    this.db = db;
    this.alertThresholds = {
      'failed_login': 5,
      'permission_denied': 10,
      'rate_limit_exceeded': 3,
      'suspicious_activity': 1
    };
  }

  async logSecurityEvent(event: SecurityEvent): Promise<void> {
    // Store the event
    await this.db.collection('securityEvents').insertOne(event);

    // Check for alert conditions
    await this.checkAlertConditions(event);

    // Log to external security systems if configured
    await this.forwardToSecuritySystems(event);
  }

  private async checkAlertConditions(event: SecurityEvent): Promise<void> {
    const threshold = this.alertThresholds[event.eventType];
    
    if (!threshold) {
      return;
    }

    // Check events in the last hour
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    
    const recentEvents = await this.db.collection('securityEvents').countDocuments({
      eventType: event.eventType,
      ip: event.ip,
      timestamp: { $gte: oneHourAgo }
    });

    if (recentEvents >= threshold) {
      await this.triggerSecurityAlert(event, recentEvents);
    }
  }

  private async triggerSecurityAlert(event: SecurityEvent, eventCount: number): Promise<void> {
    const alert = {
      alertType: 'security_threshold_exceeded',
      severity: 'high',
      eventType: event.eventType,
      ip: event.ip,
      eventCount,
      threshold: this.alertThresholds[event.eventType],
      timestamp: new Date(),
      details: {
        originalEvent: event,
        recommendation: this.getSecurityRecommendation(event.eventType)
      }
    };

    await this.db.collection('securityAlerts').insertOne(alert);

    // Send notifications (email, Slack, etc.)
    await this.sendSecurityNotification(alert);
  }

  private getSecurityRecommendation(eventType: string): string {
    const recommendations: Record<string, string> = {
      'failed_login': 'Consider implementing account lockout or CAPTCHA',
      'permission_denied': 'Review user permissions and access patterns',
      'rate_limit_exceeded': 'Consider blocking or throttling the IP address',
      'suspicious_activity': 'Investigate user behavior and consider account suspension'
    };

    return recommendations[eventType] || 'Review and investigate the security event';
  }

  private async sendSecurityNotification(alert: any): Promise<void> {
    // Implementation would send notifications via email, Slack, etc.
    console.log('Security alert triggered:', alert);
  }

  private async forwardToSecuritySystems(event: SecurityEvent): Promise<void> {
    // Forward to SIEM systems, security tools, etc.
    if (event.severity === 'critical' || event.severity === 'high') {
      // Implementation would forward to external systems
      console.log('High severity security event:', event);
    }
  }

  async getSecurityEvents(filter: {
    tenantId?: string;
    userId?: string;
    eventType?: string;
    severity?: string;
    startDate?: Date;
    endDate?: Date;
    ip?: string;
    page?: number;
    limit?: number;
  }): Promise<{
    events: SecurityEvent[];
    total: number;
    page: number;
    limit: number;
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.userId) {
      query.userId = filter.userId;
    }
    
    if (filter.eventType) {
      query.eventType = filter.eventType;
    }
    
    if (filter.severity) {
      query.severity = filter.severity;
    }
    
    if (filter.ip) {
      query.ip = filter.ip;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const page = filter.page || 1;
    const limit = filter.limit || 50;
    const skip = (page - 1) * limit;

    const [events, total] = await Promise.all([
      this.db.collection('securityEvents')
        .find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      this.db.collection('securityEvents').countDocuments(query)
    ]);

    return {
      events,
      total,
      page,
      limit
    };
  }

  async getSecuritySummary(filter: {
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<{
    totalEvents: number;
    eventsBySeverity: Record<string, number>;
    eventsByType: Record<string, number>;
    topIPs: Array<{ ip: string; count: number }>;
    recentAlerts: any[];
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const [events, alerts] = await Promise.all([
      this.db.collection('securityEvents').find(query).toArray(),
      this.db.collection('securityAlerts')
        .find({ timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } })
        .sort({ timestamp: -1 })
        .limit(10)
        .toArray()
    ]);

    const eventsBySeverity: Record<string, number> = {};
    const eventsByType: Record<string, number> = {};
    const ipCounts: Record<string, number> = {};

    events.forEach(event => {
      eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;
      eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1;
      ipCounts[event.ip] = (ipCounts[event.ip] || 0) + 1;
    });

    const topIPs = Object.entries(ipCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    return {
      totalEvents: events.length,
      eventsBySeverity,
      eventsByType,
      topIPs,
      recentAlerts: alerts
    };
  }
}
```

### 6.4.3 Performance Metrics

```typescript
// src/services/performanceMetricsService.ts
export interface PerformanceMetric {
  timestamp: Date;
  metricType: string;
  value: number;
  unit: string;
  tags: Record<string, string>;
  tenantId?: string;
}

export class PerformanceMetricsService {
  private db: Db;
  private metricsBuffer: PerformanceMetric[] = [];
  private bufferSize = 1000;
  private flushInterval = 10000; // 10 seconds

  constructor(db: Db) {
    this.db = db;
    this.startPeriodicFlush();
  }

  recordMetric(
    metricType: string,
    value: number,
    unit: string,
    tags: Record<string, string> = {},
    tenantId?: string
  ): void {
    const metric: PerformanceMetric = {
      timestamp: new Date(),
      metricType,
      value,
      unit,
      tags,
      tenantId
    };

    this.metricsBuffer.push(metric);

    if (this.metricsBuffer.length >= this.bufferSize) {
      this.flushMetrics();
    }
  }

  recordResponseTime(
    duration: number,
    route: string,
    method: string,
    statusCode: number,
    tenantId?: string
  ): void {
    this.recordMetric('response_time', duration, 'ms', {
      route,
      method,
      status_code: statusCode.toString()
    }, tenantId);
  }

  recordThroughput(requestCount: number, tenantId?: string): void {
    this.recordMetric('throughput', requestCount, 'requests/min', {}, tenantId);
  }

  recordErrorRate(errorCount: number, totalCount: number, tenantId?: string): void {
    const errorRate = totalCount > 0 ? (errorCount / totalCount) * 100 : 0;
    this.recordMetric('error_rate', errorRate, 'percentage', {}, tenantId);
  }

  recordResourceUsage(
    cpuUsage: number,
    memoryUsage: number,
    diskUsage: number
  ): void {
    this.recordMetric('cpu_usage', cpuUsage, 'percentage');
    this.recordMetric('memory_usage', memoryUsage, 'bytes');
    this.recordMetric('disk_usage', diskUsage, 'bytes');
  }

  private async flushMetrics(): Promise<void> {
    if (this.metricsBuffer.length === 0) {
      return;
    }

    const metricsToFlush = [...this.metricsBuffer];
    this.metricsBuffer = [];

    try {
      await this.db.collection('performanceMetrics').insertMany(metricsToFlush);
    } catch (error) {
      console.error('Failed to flush performance metrics:', error);
      // Re-add metrics to buffer for retry
      this.metricsBuffer.unshift(...metricsToFlush);
    }
  }

  private startPeriodicFlush(): void {
    setInterval(() => {
      this.flushMetrics();
    }, this.flushInterval);
  }

  async getMetrics(filter: {
    metricType?: string;
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
    tags?: Record<string, string>;
  }): Promise<PerformanceMetric[]> {
    const query: any = {};
    
    if (filter.metricType) {
      query.metricType = filter.metricType;
    }
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }
    
    if (filter.tags) {
      Object.entries(filter.tags).forEach(([key, value]) => {
        query[`tags.${key}`] = value;
      });
    }

    return this.db.collection('performanceMetrics')
      .find(query)
      .sort({ timestamp: -1 })
      .limit(1000)
      .toArray();
  }

  async getAggregatedMetrics(filter: {
    metricType: string;
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
    interval: 'minute' | 'hour' | 'day';
  }): Promise<Array<{
    timestamp: Date;
    avg: number;
    min: number;
    max: number;
    count: number;
  }>> {
    const query: any = { metricType: filter.metricType };
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const groupBy = this.getGroupByExpression(filter.interval);

    const pipeline = [
      { $match: query },
      {
        $group: {
          _id: groupBy,
          avg: { $avg: '$value' },
          min: { $min: '$value' },
          max: { $max: '$value' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id': 1 } },
      {
        $project: {
          timestamp: '$_id',
          avg: { $round: ['$avg', 2] },
          min: '$min',
          max: '$max',
          count: '$count'
        }
      }
    ];

    return this.db.collection('performanceMetrics').aggregate(pipeline).toArray();
  }

  private getGroupByExpression(interval: string): any {
    switch (interval) {
      case 'minute':
        return {
          year: { $year: '$timestamp' },
          month: { $month: '$timestamp' },
          day: { $dayOfMonth: '$timestamp' },
          hour: { $hour: '$timestamp' },
          minute: { $minute: '$timestamp' }
        };
      case 'hour':
        return {
          year: { $year: '$timestamp' },
          month: { $month: '$timestamp' },
          day: { $dayOfMonth: '$timestamp' },
          hour: { $hour: '$timestamp' }
        };
      case 'day':
        return {
          year: { $year: '$timestamp' },
          month: { $month: '$timestamp' },
          day: { $dayOfMonth: '$timestamp' }
        };
      default:
        return '$timestamp';
    }
  }

  async getPerformanceSummary(tenantId?: string): Promise<{
    averageResponseTime: number;
    throughput: number;
    errorRate: number;
    uptime: number;
    slowestEndpoints: Array<{ endpoint: string; avgResponseTime: number }>;
  }> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const query: any = {
      timestamp: { $gte: oneHourAgo }
    };

    if (tenantId) {
      query.tenantId = tenantId;
    }

    const [responseTimeMetrics, throughputMetrics, errorRateMetrics] = await Promise.all([
      this.db.collection('performanceMetrics')
        .find({ ...query, metricType: 'response_time' })
        .toArray(),
      this.db.collection('performanceMetrics')
        .find({ ...query, metricType: 'throughput' })
        .toArray(),
      this.db.collection('performanceMetrics')
        .find({ ...query, metricType: 'error_rate' })
        .toArray()
    ]);

    const averageResponseTime = responseTimeMetrics.length > 0
      ? responseTimeMetrics.reduce((sum, m) => sum + m.value, 0) / responseTimeMetrics.length
      : 0;

    const throughput = throughputMetrics.length > 0
      ? throughputMetrics.reduce((sum, m) => sum + m.value, 0) / throughputMetrics.length
      : 0;

    const errorRate = errorRateMetrics.length > 0
      ? errorRateMetrics.reduce((sum, m) => sum + m.value, 0) / errorRateMetrics.length
      : 0;

    // Calculate uptime (simplified)
    const uptime = 99.9; // This would be calculated based on health checks

    // Get slowest endpoints
    const endpointResponseTimes: Record<string, number[]> = {};
    responseTimeMetrics.forEach(metric => {
      const endpoint = metric.tags.route || 'unknown';
      if (!endpointResponseTimes[endpoint]) {
        endpointResponseTimes[endpoint] = [];
      }
      endpointResponseTimes[endpoint].push(metric.value);
    });

    const slowestEndpoints = Object.entries(endpointResponseTimes)
      .map(([endpoint, times]) => ({
        endpoint,
        avgResponseTime: times.reduce((sum, time) => sum + time, 0) / times.length
      }))
      .sort((a, b) => b.avgResponseTime - a.avgResponseTime)
      .slice(0, 5);

    return {
      averageResponseTime: Math.round(averageResponseTime),
      throughput: Math.round(throughput),
      errorRate: Math.round(errorRate * 100) / 100,
      uptime,
      slowestEndpoints
    };
  }
}
```

### 6.4.4 Audit Trail Implementation

```typescript
// src/services/auditTrailService.ts
export interface AuditEvent {
  timestamp: Date;
  eventId: string;
  eventType: string;
  actor: {
    userId?: string;
    userEmail?: string;
    userAgent?: string;
    ip: string;
  };
  target: {
    resourceType: string;
    resourceId?: string;
    resourceName?: string;
  };
  action: string;
  outcome: 'success' | 'failure';
  details: any;
  tenantId?: string;
  sessionId?: string;
  requestId?: string;
}

export class AuditTrailService {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  async logAuditEvent(event: Omit<AuditEvent, 'eventId' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      ...event,
      eventId: this.generateEventId(),
      timestamp: new Date()
    };

    await this.db.collection('auditTrail').insertOne(auditEvent);

    // Check for compliance requirements
    await this.checkComplianceRequirements(auditEvent);
  }

  private generateEventId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async checkComplianceRequirements(event: AuditEvent): Promise<void> {
    // Check if this event type requires special handling for compliance
    const sensitiveActions = [
      'user_created',
      'user_deleted',
      'role_assigned',
      'permission_granted',
      'data_exported',
      'data_deleted'
    ];

    if (sensitiveActions.includes(event.action)) {
      await this.createComplianceRecord(event);
    }
  }

  private async createComplianceRecord(event: AuditEvent): Promise<void> {
    const complianceRecord = {
      auditEventId: event.eventId,
      complianceType: 'data_protection',
      timestamp: event.timestamp,
      tenantId: event.tenantId,
      action: event.action,
      actor: event.actor,
      target: event.target,
      retentionPeriod: this.getRetentionPeriod(event.action),
      isArchived: false
    };

    await this.db.collection('complianceRecords').insertOne(complianceRecord);
  }

  private getRetentionPeriod(action: string): number {
    // Return retention period in days based on action type
    const retentionPeriods: Record<string, number> = {
      'user_created': 2555, // 7 years
      'user_deleted': 2555,
      'role_assigned': 1825, // 5 years
      'permission_granted': 1825,
      'data_exported': 2555,
      'data_deleted': 2555
    };

    return retentionPeriods[action] || 365; // Default 1 year
  }

  async getAuditTrail(filter: {
    tenantId?: string;
    userId?: string;
    eventType?: string;
    action?: string;
    resourceType?: string;
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    outcome?: 'success' | 'failure';
    page?: number;
    limit?: number;
  }): Promise<{
    events: AuditEvent[];
    total: number;
    page: number;
    limit: number;
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.userId) {
      query['actor.userId'] = filter.userId;
    }
    
    if (filter.eventType) {
      query.eventType = filter.eventType;
    }
    
    if (filter.action) {
      query.action = filter.action;
    }
    
    if (filter.resourceType) {
      query['target.resourceType'] = filter.resourceType;
    }
    
    if (filter.resourceId) {
      query['target.resourceId'] = filter.resourceId;
    }
    
    if (filter.outcome) {
      query.outcome = filter.outcome;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const page = filter.page || 1;
    const limit = filter.limit || 50;
    const skip = (page - 1) * limit;

    const [events, total] = await Promise.all([
      this.db.collection('auditTrail')
        .find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      this.db.collection('auditTrail').countDocuments(query)
    ]);

    return {
      events,
      total,
      page,
      limit
    };
  }

  async exportAuditTrail(filter: {
    tenantId?: string;
    startDate: Date;
    endDate: Date;
    format: 'json' | 'csv';
  }): Promise<string> {
    const query: any = {
      timestamp: {
        $gte: filter.startDate,
        $lte: filter.endDate
      }
    };
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }

    const events = await this.db.collection('auditTrail')
      .find(query)
      .sort({ timestamp: 1 })
      .toArray();

    if (filter.format === 'csv') {
      return this.convertToCSV(events);
    } else {
      return JSON.stringify(events, null, 2);
    }
  }

  private convertToCSV(events: AuditEvent[]): string {
    if (events.length === 0) {
      return '';
    }

    const headers = [
      'Timestamp',
      'Event ID',
      'Event Type',
      'Action',
      'Outcome',
      'User ID',
      'User Email',
      'IP Address',
      'Resource Type',
      'Resource ID',
      'Tenant ID'
    ];

    const rows = events.map(event => [
      event.timestamp.toISOString(),
      event.eventId,
      event.eventType,
      event.action,
      event.outcome,
      event.actor.userId || '',
      event.actor.userEmail || '',
      event.actor.ip,
      event.target.resourceType,
      event.target.resourceId || '',
      event.tenantId || ''
    ]);

    return [headers, ...rows]
      .map(row => row.map(field => `"${field}"`).join(','))
      .join('\n');
  }

  async getAuditSummary(filter: {
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsByAction: Record<string, number>;
    eventsByOutcome: Record<string, number>;
    topUsers: Array<{ userId: string; userEmail: string; eventCount: number }>;
    recentEvents: AuditEvent[];
  }> {
    const query: any = {};
    
    if (filter.tenantId) {
      query.tenantId = filter.tenantId;
    }
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) {
        query.timestamp.$gte = filter.startDate;
      }
      if (filter.endDate) {
        query.timestamp.$lte = filter.endDate;
      }
    }

    const [events, recentEvents] = await Promise.all([
      this.db.collection('auditTrail').find(query).toArray(),
      this.db.collection('auditTrail')
        .find(query)
        .sort({ timestamp: -1 })
        .limit(10)
        .toArray()
    ]);

    const eventsByType: Record<string, number> = {};
    const eventsByAction: Record<string, number> = {};
    const eventsByOutcome: Record<string, number> = {};
    const userCounts: Record<string, { userEmail: string; count: number }> = {};

    events.forEach(event => {
      eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1;
      eventsByAction[event.action] = (eventsByAction[event.action] || 0) + 1;
      eventsByOutcome[event.outcome] = (eventsByOutcome[event.outcome] || 0) + 1;

      if (event.actor.userId) {
        if (!userCounts[event.actor.userId]) {
          userCounts[event.actor.userId] = {
            userEmail: event.actor.userEmail || '',
            count: 0
          };
        }
        userCounts[event.actor.userId].count++;
      }
    });

    const topUsers = Object.entries(userCounts)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 10)
      .map(([userId, data]) => ({
        userId,
        userEmail: data.userEmail,
        eventCount: data.count
      }));

    return {
      totalEvents: events.length,
      eventsByType,
      eventsByAction,
      eventsByOutcome,
      topUsers,
      recentEvents
    };
  }

  async cleanupOldAuditRecords(): Promise<void> {
    // Clean up audit records based on retention policies
    const retentionPeriod = 2555; // 7 years in days
    const cutoffDate = new Date(Date.now() - retentionPeriod * 24 * 60 * 60 * 1000);

    const result = await this.db.collection('auditTrail').deleteMany({
      timestamp: { $lt: cutoffDate }
    });

    console.log(`Cleaned up ${result.deletedCount} old audit records`);
  }
}
```

## Integration with Fastify

```typescript
// src/plugins/gatewayPlugin.ts
export async function gatewayPlugin(fastify: FastifyInstance) {
  // Register services
  const routeMatchingService = new RouteMatchingService(fastify.mongo.db);
  const serviceDiscoveryService = new ServiceDiscoveryService(fastify.mongo.db);
  const loadBalancerService = new LoadBalancerService();
  const circuitBreakerService = new CircuitBreakerService();
  const proxyService = new ProxyService(
    serviceDiscoveryService,
    loadBalancerService,
    circuitBreakerService
  );

  // Register middleware
  fastify.addHook('preHandler', authenticationMiddleware);
  fastify.addHook('preHandler', tenantValidationMiddleware);

  // Main gateway route handler
  fastify.all('/*', async (request, reply) => {
    const route = routeMatchingService.findMatchingRoute(
      request.user.tenantId,
      request.method,
      request.url
    );

    if (!route) {
      return reply.code(404).send({
        error: 'Not Found',
        message: 'No route configured for this request'
      });
    }

    // Apply route-specific middleware
    if (route.authentication.required) {
      const hasPermission = await checkUserPermissions(
        request.user.userId,
        request.user.tenantId,
        route.authentication.permissions,
        request
      );

      if (!hasPermission) {
        return reply.code(403).send({
          error: 'Forbidden',
          message: 'Insufficient permissions for this route'
        });
      }
    }

    // Apply rate limiting
    if (route.rateLimit.enabled) {
      const rateLimitResult = await applyRateLimit(request, route.rateLimit);
      if (!rateLimitResult.allowed) {
        return reply.code(429).send({
          error: 'Too Many Requests',
          message: 'Rate limit exceeded'
        });
      }
    }

    // Proxy the request
    await proxyService.proxyRequest(request, reply, route);
  });
}
```

This completes the comprehensive API Gateway Core documentation covering request routing, middleware pipeline, proxy implementation, and audit logging. The implementation provides a robust foundation for handling multi-tenant API requests with proper authentication, authorization, routing, and monitoring capabilities. 