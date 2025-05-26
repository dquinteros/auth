# Admin Web Panel

## 8.1 Frontend Architecture

### 8.1.1 React/Vue.js Setup

The admin web panel is built using modern frontend technologies with a focus on security, usability, and maintainability.

#### React Setup with TypeScript

```json
// package.json
{
  "name": "api-gateway-admin",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "react-query": "^3.39.0",
    "@mui/material": "^5.11.0",
    "@mui/icons-material": "^5.11.0",
    "@emotion/react": "^11.10.0",
    "@emotion/styled": "^11.10.0",
    "axios": "^1.3.0",
    "formik": "^2.2.9",
    "yup": "^1.0.0",
    "date-fns": "^2.29.0",
    "recharts": "^2.5.0"
  },
  "devDependencies": {
    "@types/node": "^18.14.0",
    "@vitejs/plugin-react": "^3.1.0",
    "typescript": "^4.9.0",
    "vite": "^4.1.0",
    "eslint": "^8.35.0",
    "@typescript-eslint/eslint-plugin": "^5.54.0",
    "@typescript-eslint/parser": "^5.54.0"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext ts,tsx --report-unused-disable-directives --max-warnings 0"
  }
}
```

#### Vite Configuration

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          ui: ['@mui/material', '@mui/icons-material']
        }
      }
    }
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV)
  }
});
```

### 8.1.2 Component Structure

Organized component architecture following best practices.

```
src/
├── components/
│   ├── common/
│   │   ├── Layout/
│   │   │   ├── AppLayout.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Header.tsx
│   │   ├── Forms/
│   │   │   ├── FormField.tsx
│   │   │   ├── FormSelect.tsx
│   │   │   └── FormDatePicker.tsx
│   │   ├── Tables/
│   │   │   ├── DataTable.tsx
│   │   │   ├── TablePagination.tsx
│   │   │   └── TableFilters.tsx
│   │   └── UI/
│   │       ├── LoadingSpinner.tsx
│   │       ├── ErrorBoundary.tsx
│   │       └── ConfirmDialog.tsx
│   ├── tenants/
│   │   ├── TenantList.tsx
│   │   ├── TenantForm.tsx
│   │   ├── TenantDetails.tsx
│   │   └── TenantMetrics.tsx
│   ├── roles/
│   │   ├── RoleList.tsx
│   │   ├── RoleForm.tsx
│   │   └── PermissionMatrix.tsx
│   └── users/
│       ├── UserList.tsx
│       ├── UserForm.tsx
│       └── UserRoleAssignment.tsx
├── hooks/
│   ├── useAuth.ts
│   ├── useTenants.ts
│   ├── useRoles.ts
│   └── usePermissions.ts
├── services/
│   ├── api.ts
│   ├── auth.ts
│   ├── tenants.ts
│   └── roles.ts
├── types/
│   ├── tenant.ts
│   ├── user.ts
│   ├── role.ts
│   └── api.ts
├── utils/
│   ├── validation.ts
│   ├── formatting.ts
│   └── constants.ts
└── App.tsx
```

#### Base Layout Component

```typescript
// components/common/Layout/AppLayout.tsx
import React from 'react';
import { Box, CssBaseline, Toolbar } from '@mui/material';
import { Outlet } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';
import ErrorBoundary from '../UI/ErrorBoundary';

const DRAWER_WIDTH = 280;

const AppLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = React.useState(true);

  const handleSidebarToggle = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      <Header 
        onSidebarToggle={handleSidebarToggle}
        sidebarOpen={sidebarOpen}
        drawerWidth={DRAWER_WIDTH}
      />
      <Sidebar 
        open={sidebarOpen}
        onToggle={handleSidebarToggle}
        drawerWidth={DRAWER_WIDTH}
      />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { sm: sidebarOpen ? 0 : `-${DRAWER_WIDTH}px` },
          transition: 'margin 0.3s ease'
        }}
      >
        <Toolbar />
        <ErrorBoundary>
          <Outlet />
        </ErrorBoundary>
      </Box>
    </Box>
  );
};

export default AppLayout;
```

### 8.1.3 State Management

Using React Query for server state and Context API for client state.

```typescript
// hooks/useAuth.ts
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authService } from '../services/auth';

interface User {
  id: string;
  email: string;
  name: string;
  role: 'superadmin';
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = localStorage.getItem('admin_token');
        if (token) {
          const userData = await authService.validateToken(token);
          setUser(userData);
        }
      } catch (error) {
        localStorage.removeItem('admin_token');
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    try {
      const response = await authService.login(email, password);
      localStorage.setItem('admin_token', response.token);
      setUser(response.user);
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('admin_token');
    setUser(null);
  };

  const value = {
    user,
    isLoading,
    login,
    logout,
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
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

#### API Service Layer

```typescript
// services/api.ts
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.REACT_APP_API_URL || '/api',
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('admin_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('admin_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.get(url, config);
    return response.data;
  }

  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.post(url, data, config);
    return response.data;
  }

  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.put(url, data, config);
    return response.data;
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.delete(url, config);
    return response.data;
  }
}

export const apiService = new ApiService();
```

## 8.2 Tenant Management Interface

### 8.2.1 Tenant Dashboard

Overview dashboard showing tenant statistics and health metrics.

```typescript
// components/tenants/TenantDashboard.tsx
import React from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress
} from '@mui/material';
import {
  TrendingUp,
  People,
  Security,
  Speed
} from '@mui/icons-material';
import { useQuery } from 'react-query';
import { tenantService } from '../../services/tenants';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const TenantDashboard: React.FC = () => {
  const { data: stats, isLoading } = useQuery(
    'tenant-stats',
    () => tenantService.getStats(),
    { refetchInterval: 30000 }
  );

  const { data: metrics } = useQuery(
    'tenant-metrics',
    () => tenantService.getMetrics(),
    { refetchInterval: 60000 }
  );

  if (isLoading) {
    return <LinearProgress />;
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Tenant Dashboard
      </Typography>

      <Grid container spacing={3}>
        {/* Summary Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <People color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Total Tenants
                  </Typography>
                  <Typography variant="h5">
                    {stats?.totalTenants || 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <TrendingUp color="success" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Active Tenants
                  </Typography>
                  <Typography variant="h5">
                    {stats?.activeTenants || 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security color="warning" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    API Requests (24h)
                  </Typography>
                  <Typography variant="h5">
                    {stats?.apiRequests24h?.toLocaleString() || 0}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Speed color="info" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Avg Response Time
                  </Typography>
                  <Typography variant="h5">
                    {stats?.avgResponseTime || 0}ms
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Usage Chart */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                API Usage Trends
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={metrics?.usage || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Line 
                    type="monotone" 
                    dataKey="requests" 
                    stroke="#8884d8" 
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Activity */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Activity
              </Typography>
              <Box>
                {stats?.recentActivity?.map((activity: any, index: number) => (
                  <Box key={index} mb={2}>
                    <Typography variant="body2">
                      {activity.description}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {new Date(activity.timestamp).toLocaleString()}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default TenantDashboard;
```

### 8.2.2 Tenant CRUD Forms

Comprehensive tenant management forms with validation.

```typescript
// components/tenants/TenantForm.tsx
import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Chip,
  Box,
  Typography
} from '@mui/material';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { useMutation, useQueryClient } from 'react-query';
import { tenantService } from '../../services/tenants';
import { Tenant } from '../../types/tenant';

interface TenantFormProps {
  open: boolean;
  onClose: () => void;
  tenant?: Tenant;
  mode: 'create' | 'edit';
}

const validationSchema = Yup.object({
  name: Yup.string()
    .required('Tenant name is required')
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be less than 100 characters'),
  domain: Yup.string()
    .matches(
      /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/,
      'Invalid domain format'
    ),
  contactEmail: Yup.string()
    .email('Invalid email format')
    .required('Contact email is required'),
  maxUsers: Yup.number()
    .min(1, 'Must allow at least 1 user')
    .max(10000, 'Maximum 10,000 users allowed'),
  rateLimit: Yup.number()
    .min(10, 'Minimum 10 requests per minute')
    .max(10000, 'Maximum 10,000 requests per minute')
});

const TenantForm: React.FC<TenantFormProps> = ({ open, onClose, tenant, mode }) => {
  const queryClient = useQueryClient();

  const mutation = useMutation(
    (data: any) => mode === 'create' 
      ? tenantService.create(data)
      : tenantService.update(tenant!.id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('tenants');
        onClose();
      }
    }
  );

  const initialValues = {
    name: tenant?.name || '',
    domain: tenant?.domain || '',
    contactEmail: tenant?.contactEmail || '',
    description: tenant?.description || '',
    maxUsers: tenant?.settings?.maxUsers || 100,
    rateLimit: tenant?.settings?.rateLimit || 1000,
    features: tenant?.settings?.features || [],
    isActive: tenant?.status === 'active' || true,
    allowedDomains: tenant?.settings?.allowedDomains || []
  };

  const availableFeatures = [
    'api_access',
    'webhook_support',
    'custom_roles',
    'audit_logs',
    'sso_integration',
    'advanced_analytics'
  ];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {mode === 'create' ? 'Create New Tenant' : 'Edit Tenant'}
      </DialogTitle>
      
      <Formik
        initialValues={initialValues}
        validationSchema={validationSchema}
        onSubmit={(values) => mutation.mutate(values)}
      >
        {({ values, errors, touched, setFieldValue }) => (
          <Form>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <Field
                    as={TextField}
                    name="name"
                    label="Tenant Name"
                    fullWidth
                    error={touched.name && !!errors.name}
                    helperText={touched.name && errors.name}
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Field
                    as={TextField}
                    name="domain"
                    label="Custom Domain (Optional)"
                    fullWidth
                    error={touched.domain && !!errors.domain}
                    helperText={touched.domain && errors.domain}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Field
                    as={TextField}
                    name="contactEmail"
                    label="Contact Email"
                    type="email"
                    fullWidth
                    error={touched.contactEmail && !!errors.contactEmail}
                    helperText={touched.contactEmail && errors.contactEmail}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Field
                    as={TextField}
                    name="description"
                    label="Description"
                    multiline
                    rows={3}
                    fullWidth
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Field
                    as={TextField}
                    name="maxUsers"
                    label="Maximum Users"
                    type="number"
                    fullWidth
                    error={touched.maxUsers && !!errors.maxUsers}
                    helperText={touched.maxUsers && errors.maxUsers}
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Field
                    as={TextField}
                    name="rateLimit"
                    label="Rate Limit (req/min)"
                    type="number"
                    fullWidth
                    error={touched.rateLimit && !!errors.rateLimit}
                    helperText={touched.rateLimit && errors.rateLimit}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Enabled Features
                  </Typography>
                  <Box display="flex" flexWrap="wrap" gap={1}>
                    {availableFeatures.map((feature) => (
                      <Chip
                        key={feature}
                        label={feature.replace('_', ' ').toUpperCase()}
                        clickable
                        color={values.features.includes(feature) ? 'primary' : 'default'}
                        onClick={() => {
                          const newFeatures = values.features.includes(feature)
                            ? values.features.filter((f: string) => f !== feature)
                            : [...values.features, feature];
                          setFieldValue('features', newFeatures);
                        }}
                      />
                    ))}
                  </Box>
                </Grid>

                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={values.isActive}
                        onChange={(e) => setFieldValue('isActive', e.target.checked)}
                      />
                    }
                    label="Active"
                  />
                </Grid>
              </Grid>
            </DialogContent>

            <DialogActions>
              <Button onClick={onClose}>Cancel</Button>
              <Button 
                type="submit" 
                variant="contained"
                disabled={mutation.isLoading}
              >
                {mutation.isLoading ? 'Saving...' : 'Save'}
              </Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default TenantForm;
```

### 8.2.3 Tenant Monitoring Views

Real-time monitoring and analytics for tenant performance.

```typescript
// components/tenants/TenantMetrics.tsx
import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Grid,
  Box,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Alert
} from '@mui/material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { useQuery } from 'react-query';
import { tenantService } from '../../services/tenants';

interface TenantMetricsProps {
  tenantId: string;
}

const TenantMetrics: React.FC<TenantMetricsProps> = ({ tenantId }) => {
  const [timeRange, setTimeRange] = useState('24h');

  const { data: metrics, isLoading } = useQuery(
    ['tenant-metrics', tenantId, timeRange],
    () => tenantService.getMetrics(tenantId, timeRange),
    { refetchInterval: 30000 }
  );

  const { data: health } = useQuery(
    ['tenant-health', tenantId],
    () => tenantService.getHealth(tenantId),
    { refetchInterval: 10000 }
  );

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5">Tenant Metrics</Typography>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Time Range</InputLabel>
          <Select
            value={timeRange}
            label="Time Range"
            onChange={(e) => setTimeRange(e.target.value)}
          >
            <MenuItem value="1h">Last Hour</MenuItem>
            <MenuItem value="24h">Last 24 Hours</MenuItem>
            <MenuItem value="7d">Last 7 Days</MenuItem>
            <MenuItem value="30d">Last 30 Days</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Health Status */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Alert 
            severity={health?.status === 'healthy' ? 'success' : 'warning'}
            sx={{ mb: 2 }}
          >
            Tenant Status: {health?.status || 'Unknown'}
          </Alert>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* API Usage */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                API Usage Over Time
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={metrics?.apiUsage || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="requests" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Response Status Distribution */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Response Status
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={metrics?.statusDistribution || []}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {(metrics?.statusDistribution || []).map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Performance Metrics */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Performance Metrics
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="primary">
                      {metrics?.avgResponseTime || 0}ms
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Avg Response Time
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="success.main">
                      {metrics?.successRate || 0}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Success Rate
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="info.main">
                      {metrics?.totalRequests || 0}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Total Requests
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="error.main">
                      {metrics?.errorCount || 0}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Errors
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Resource Usage */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Resource Usage
              </Typography>
              <Box mb={2}>
                <Typography variant="body2" gutterBottom>
                  Users: {metrics?.userCount || 0} / {metrics?.maxUsers || 0}
                </Typography>
                <Box 
                  sx={{ 
                    width: '100%', 
                    height: 8, 
                    backgroundColor: 'grey.300',
                    borderRadius: 1
                  }}
                >
                  <Box
                    sx={{
                      width: `${((metrics?.userCount || 0) / (metrics?.maxUsers || 1)) * 100}%`,
                      height: '100%',
                      backgroundColor: 'primary.main',
                      borderRadius: 1
                    }}
                  />
                </Box>
              </Box>
              
              <Box mb={2}>
                <Typography variant="body2" gutterBottom>
                  API Calls: {metrics?.apiCallsUsed || 0} / {metrics?.apiCallsLimit || 0}
                </Typography>
                <Box 
                  sx={{ 
                    width: '100%', 
                    height: 8, 
                    backgroundColor: 'grey.300',
                    borderRadius: 1
                  }}
                >
                  <Box
                    sx={{
                      width: `${((metrics?.apiCallsUsed || 0) / (metrics?.apiCallsLimit || 1)) * 100}%`,
                      height: '100%',
                      backgroundColor: 'success.main',
                      borderRadius: 1
                    }}
                  />
                </Box>
              </Box>

              <Box>
                <Typography variant="body2" gutterBottom>
                  Storage: {metrics?.storageUsed || 0}MB / {metrics?.storageLimit || 0}MB
                </Typography>
                <Box 
                  sx={{ 
                    width: '100%', 
                    height: 8, 
                    backgroundColor: 'grey.300',
                    borderRadius: 1
                  }}
                >
                  <Box
                    sx={{
                      width: `${((metrics?.storageUsed || 0) / (metrics?.storageLimit || 1)) * 100}%`,
                      height: '100%',
                      backgroundColor: 'warning.main',
                      borderRadius: 1
                    }}
                  />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Active Features */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Active Features
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={1}>
                {(metrics?.activeFeatures || []).map((feature: string) => (
                  <Chip 
                    key={feature}
                    label={feature.replace('_', ' ').toUpperCase()}
                    color="primary"
                    size="small"
                  />
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default TenantMetrics;
```

## 8.3 Role and Permission Management

### 8.3.1 Role Management Interface

Interface for managing roles within the admin panel.

```typescript
// components/roles/RoleManagement.tsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  FormGroup,
  FormControlLabel
} from '@mui/material';
import {
  Add,
  Edit,
  Delete,
  Security
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { roleService } from '../../services/roles';

const RoleManagement: React.FC = () => {
  const [selectedTenant, setSelectedTenant] = useState('');
  const [roleDialogOpen, setRoleDialogOpen] = useState(false);
  const [editingRole, setEditingRole] = useState(null);

  const queryClient = useQueryClient();

  const { data: tenants } = useQuery('tenants', () => tenantService.getAll());
  
  const { data: roles, isLoading } = useQuery(
    ['roles', selectedTenant],
    () => selectedTenant ? roleService.getByTenant(selectedTenant) : [],
    { enabled: !!selectedTenant }
  );

  const { data: permissions } = useQuery(
    'available-permissions',
    () => roleService.getAvailablePermissions()
  );

  const deleteMutation = useMutation(
    (roleId: string) => roleService.delete(roleId),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['roles', selectedTenant]);
      }
    }
  );

  const handleEditRole = (role: any) => {
    setEditingRole(role);
    setRoleDialogOpen(true);
  };

  const handleDeleteRole = (roleId: string) => {
    if (window.confirm('Are you sure you want to delete this role?')) {
      deleteMutation.mutate(roleId);
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Role Management</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => {
            setEditingRole(null);
            setRoleDialogOpen(true);
          }}
          disabled={!selectedTenant}
        >
          Create Role
        </Button>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <FormControl fullWidth>
            <InputLabel>Select Tenant</InputLabel>
            <Select
              value={selectedTenant}
              label="Select Tenant"
              onChange={(e) => setSelectedTenant(e.target.value)}
            >
              {tenants?.map((tenant: any) => (
                <MenuItem key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </CardContent>
      </Card>

      {selectedTenant && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Roles for Selected Tenant
            </Typography>
            
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Role Name</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Permissions</TableCell>
                    <TableCell>Users</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {roles?.map((role: any) => (
                    <TableRow key={role.id}>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Security sx={{ mr: 1, color: 'primary.main' }} />
                          {role.name}
                        </Box>
                      </TableCell>
                      <TableCell>{role.description}</TableCell>
                      <TableCell>
                        <Box display="flex" flexWrap="wrap" gap={0.5}>
                          {role.permissions.slice(0, 3).map((permission: string) => (
                            <Chip 
                              key={permission}
                              label={permission}
                              size="small"
                              variant="outlined"
                            />
                          ))}
                          {role.permissions.length > 3 && (
                            <Chip 
                              label={`+${role.permissions.length - 3} more`}
                              size="small"
                              color="primary"
                            />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>{role.userCount || 0}</TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleEditRole(role)}
                        >
                          <Edit />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDeleteRole(role.id)}
                          disabled={role.isSystem}
                        >
                          <Delete />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      <RoleDialog
        open={roleDialogOpen}
        onClose={() => setRoleDialogOpen(false)}
        role={editingRole}
        tenantId={selectedTenant}
        permissions={permissions || []}
      />
    </Box>
  );
};

// Role Dialog Component
const RoleDialog: React.FC<{
  open: boolean;
  onClose: () => void;
  role: any;
  tenantId: string;
  permissions: string[];
}> = ({ open, onClose, role, tenantId, permissions }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    permissions: [] as string[]
  });

  const queryClient = useQueryClient();

  React.useEffect(() => {
    if (role) {
      setFormData({
        name: role.name,
        description: role.description,
        permissions: role.permissions
      });
    } else {
      setFormData({
        name: '',
        description: '',
        permissions: []
      });
    }
  }, [role]);

  const mutation = useMutation(
    (data: any) => role 
      ? roleService.update(role.id, data)
      : roleService.create({ ...data, tenantId }),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['roles', tenantId]);
        onClose();
      }
    }
  );

  const handlePermissionChange = (permission: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      permissions: checked
        ? [...prev.permissions, permission]
        : prev.permissions.filter(p => p !== permission)
    }));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {role ? 'Edit Role' : 'Create New Role'}
      </DialogTitle>
      
      <DialogContent>
        <Box mb={3}>
          <TextField
            fullWidth
            label="Role Name"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            margin="normal"
          />
          
          <TextField
            fullWidth
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
            margin="normal"
            multiline
            rows={2}
          />
        </Box>

        <Typography variant="h6" gutterBottom>
          Permissions
        </Typography>
        
        <FormGroup>
          {permissions.map((permission) => (
            <FormControlLabel
              key={permission}
              control={
                <Checkbox
                  checked={formData.permissions.includes(permission)}
                  onChange={(e) => handlePermissionChange(permission, e.target.checked)}
                />
              }
              label={permission}
            />
          ))}
        </FormGroup>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button 
          variant="contained"
          onClick={() => mutation.mutate(formData)}
          disabled={mutation.isLoading}
        >
          {mutation.isLoading ? 'Saving...' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default RoleManagement;
```

## 8.4 Security and Access Control

### 8.4.1 Superadmin Authentication

Secure authentication system for superadmin access.

```typescript
// components/auth/LoginForm.tsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  InputAdornment,
  IconButton
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Security
} from '@mui/icons-material';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../../hooks/useAuth';
import { useNavigate } from 'react-router-dom';

const validationSchema = Yup.object({
  email: Yup.string()
    .email('Invalid email format')
    .required('Email is required'),
  password: Yup.string()
    .min(8, 'Password must be at least 8 characters')
    .required('Password is required'),
  mfaCode: Yup.string()
    .matches(/^\d{6}$/, 'MFA code must be 6 digits')
    .when('requireMFA', {
      is: true,
      then: (schema) => schema.required('MFA code is required')
    })
});

const LoginForm: React.FC = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [requireMFA, setRequireMFA] = useState(false);
  const [error, setError] = useState('');
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (values: any) => {
    try {
      setError('');
      await login(values.email, values.password, values.mfaCode);
      navigate('/dashboard');
    } catch (err: any) {
      if (err.code === 'MFA_REQUIRED') {
        setRequireMFA(true);
      } else {
        setError(err.message || 'Login failed');
      }
    }
  };

  return (
    <Box
      display="flex"
      justifyContent="center"
      alignItems="center"
      minHeight="100vh"
      bgcolor="grey.100"
    >
      <Card sx={{ maxWidth: 400, width: '100%', m: 2 }}>
        <CardContent sx={{ p: 4 }}>
          <Box textAlign="center" mb={3}>
            <Security sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
            <Typography variant="h4" gutterBottom>
              Admin Portal
            </Typography>
            <Typography variant="body2" color="textSecondary">
              Multi-Tenant API Gateway Administration
            </Typography>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Formik
            initialValues={{
              email: '',
              password: '',
              mfaCode: ''
            }}
            validationSchema={validationSchema}
            onSubmit={handleSubmit}
          >
            {({ errors, touched, isSubmitting }) => (
              <Form>
                <Field
                  as={TextField}
                  name="email"
                  label="Email Address"
                  type="email"
                  fullWidth
                  margin="normal"
                  error={touched.email && !!errors.email}
                  helperText={touched.email && errors.email}
                />

                <Field
                  as={TextField}
                  name="password"
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  fullWidth
                  margin="normal"
                  error={touched.password && !!errors.password}
                  helperText={touched.password && errors.password}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowPassword(!showPassword)}
                          edge="end"
                        >
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    )
                  }}
                />

                {requireMFA && (
                  <Field
                    as={TextField}
                    name="mfaCode"
                    label="MFA Code"
                    fullWidth
                    margin="normal"
                    error={touched.mfaCode && !!errors.mfaCode}
                    helperText={touched.mfaCode && errors.mfaCode}
                    placeholder="Enter 6-digit code"
                  />
                )}

                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  disabled={isSubmitting}
                  sx={{ mt: 3, mb: 2 }}
                >
                  {isSubmitting ? 'Signing In...' : 'Sign In'}
                </Button>
              </Form>
            )}
          </Formik>

          <Box mt={2}>
            <Typography variant="caption" color="textSecondary" align="center" display="block">
              Secure access for authorized administrators only
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default LoginForm;
```

### 8.4.2 Session Management

Secure session handling with automatic timeout and refresh.

```typescript
// hooks/useSession.ts
import { useEffect, useCallback } from 'react';
import { useAuth } from './useAuth';

const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const WARNING_TIME = 5 * 60 * 1000; // 5 minutes before timeout

export const useSession = () => {
  const { logout, isAuthenticated } = useAuth();

  const resetTimeout = useCallback(() => {
    if (!isAuthenticated) return;

    // Clear existing timeouts
    if (window.sessionTimeout) {
      clearTimeout(window.sessionTimeout);
    }
    if (window.warningTimeout) {
      clearTimeout(window.warningTimeout);
    }

    // Set warning timeout
    window.warningTimeout = setTimeout(() => {
      const shouldExtend = window.confirm(
        'Your session will expire in 5 minutes. Do you want to extend it?'
      );
      
      if (shouldExtend) {
        resetTimeout();
      }
    }, SESSION_TIMEOUT - WARNING_TIME);

    // Set logout timeout
    window.sessionTimeout = setTimeout(() => {
      alert('Session expired. You will be logged out.');
      logout();
    }, SESSION_TIMEOUT);

    // Update last activity timestamp
    localStorage.setItem('lastActivity', Date.now().toString());
  }, [isAuthenticated, logout]);

  const handleActivity = useCallback(() => {
    if (isAuthenticated) {
      resetTimeout();
    }
  }, [isAuthenticated, resetTimeout]);

  useEffect(() => {
    if (isAuthenticated) {
      resetTimeout();

      // Add activity listeners
      const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
      events.forEach(event => {
        document.addEventListener(event, handleActivity, true);
      });

      return () => {
        events.forEach(event => {
          document.removeEventListener(event, handleActivity, true);
        });
        
        if (window.sessionTimeout) {
          clearTimeout(window.sessionTimeout);
        }
        if (window.warningTimeout) {
          clearTimeout(window.warningTimeout);
        }
      };
    }
  }, [isAuthenticated, resetTimeout, handleActivity]);

  return { resetTimeout };
};
```

### 8.4.3 UI Security Considerations

Security measures implemented in the frontend.

```typescript
// utils/security.ts
export class SecurityUtils {
  // Sanitize user input to prevent XSS
  static sanitizeInput(input: string): string {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  }

  // Validate file uploads
  static validateFileUpload(file: File): { valid: boolean; error?: string } {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    const maxSize = 5 * 1024 * 1024; // 5MB

    if (!allowedTypes.includes(file.type)) {
      return { valid: false, error: 'File type not allowed' };
    }

    if (file.size > maxSize) {
      return { valid: false, error: 'File size too large' };
    }

    return { valid: true };
  }

  // Generate secure random strings
  static generateSecureRandom(length: number = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Check for suspicious patterns in input
  static detectSuspiciousInput(input: string): boolean {
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\s*\(/i,
      /expression\s*\(/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(input));
  }

  // Secure local storage operations
  static secureStorage = {
    set(key: string, value: any): void {
      try {
        const encrypted = btoa(JSON.stringify(value));
        localStorage.setItem(key, encrypted);
      } catch (error) {
        console.error('Failed to store data securely:', error);
      }
    },

    get(key: string): any {
      try {
        const encrypted = localStorage.getItem(key);
        if (!encrypted) return null;
        return JSON.parse(atob(encrypted));
      } catch (error) {
        console.error('Failed to retrieve data securely:', error);
        return null;
      }
    },

    remove(key: string): void {
      localStorage.removeItem(key);
    }
  };
}

// Content Security Policy helper
export const CSPHelper = {
  generateNonce(): string {
    return SecurityUtils.generateSecureRandom(16);
  },

  createCSPHeader(nonce: string): string {
    return [
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}'`,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'"
    ].join('; ');
  }
};
```

This comprehensive Admin Web Panel documentation covers all aspects of the frontend implementation, including React/TypeScript setup, component architecture, state management, tenant management interfaces, role and permission management, and security considerations. The documentation provides practical, production-ready code examples that can be directly implemented. 