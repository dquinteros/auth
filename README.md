# Multi-Tenant API Gateway

This repository contains a Node.js based API Gateway designed for multi-tenant applications. The gateway handles authentication, authorization and request routing across multiple backend services. It integrates with AWS Cognito for user management and uses MongoDB for data storage.

## Quick Start

1. **Install dependencies**

```bash
npm install
```

2. **Start the development environment**

```bash
docker-compose up -d        # start MongoDB and other services
npm run dev:api             # start the API Gateway
```

The gateway will be available at `http://localhost:3000`. See [docs/02-getting-started.md](docs/02-getting-started.md) for detailed setup instructions.

## Running the Server

Once the server implementation is complete you can run it with:

```bash
npm run dev:api
```

Additional documentation for architecture, authentication and deployment can be found in the [docs/](docs/) directory.
