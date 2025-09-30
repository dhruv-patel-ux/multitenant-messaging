# Multi-Tenant Messaging Microservice

Enterprise-grade multi-tenant messaging microservice built with NestJS that wraps WAHA (WhatsApp HTTP API) for outbound/inbound WhatsApp messaging with secure REST API and RBAC.

## 🚀 Quick Start (5-minute setup)

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 15+ (or use Docker)

### Installation

```bash
# Clone and install
git clone <repository-url>
cd multitenant-messaging-api
npm install

# Environment setup
cp .env.example .env.development
# Edit .env.development with your settings

# Start all services
docker-compose up -d

# Run migrations
npm run typeorm:migration:run

# Seed demo data
npm run seed:demo

# Start development server
npm run start:dev
```

- **API**: http://localhost:3000
- **Swagger docs**: http://localhost:3000/api/docs
- **WAHA dashboard**: http://localhost:3001

## 🏗️ Architecture Overview

### Tech Stack
- **Framework**: NestJS 10+ with TypeScript
- **Database**: PostgreSQL with TypeORM
- **Authentication**: JWT with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **Integration**: WAHA (WhatsApp HTTP API)
- **Caching**: Redis for sessions and rate limiting
- **Documentation**: Swagger/OpenAPI 3.0

### Multi-Tenancy
- Row-level tenant isolation with `tenant_id`
- Tenant-specific user management
- Isolated WAHA sessions per tenant
- Cross-tenant data access prevention

### Security Features
- JWT access tokens (15min) + refresh tokens (7days)
- Password hashing with bcrypt (12 rounds)
- Rate limiting and account lockout
- Input validation and sanitization
- CORS and security headers
- Webhook signature validation

## 📋 API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Current user profile

### Users (Tenant Admin)
- `POST /users` - Create user
- `GET /users` - List users
- `GET /users/:id` - Get user by ID
- `PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user

### WAHA Sessions
- `POST /waha/sessions` - Create & start session
- `GET /waha/sessions` - List tenant sessions
- `GET /waha/sessions/:id` - Get session details
- `GET /waha/sessions/:id/qr` - Get QR code
- `POST /waha/sessions/:id/stop` - Stop session
- `DELETE /waha/sessions/:id` - Delete session

### Messaging
- `POST /messages/send` - Send message
- `POST /messages/bulk` - Bulk messaging
- `GET /messages` - List messages with filters
- `GET /messages/:id` - Get message by ID
- `GET /messages/stats` - Messaging statistics
- `POST /messages/:id/retry` - Retry failed message

### Webhooks
- `POST /webhooks/waha` - WAHA webhook endpoint
- `GET /webhooks/health` - Webhook health check

### Health & Monitoring
- `GET /health` - API health status
- `GET /health/db` - Database connection
- `GET /ready` - System readiness
- `GET /metrics` - Prometheus metrics

## 👥 User Roles & Permissions

| Role | Permissions |
|------|-------------|
| **TENANT_ADMIN** | Full tenant control, user management, all operations |
| **MANAGER** | Create campaigns, send messages, view reports |
| **AGENT** | Send/receive messages, view assigned conversations |
| **AUDITOR** | Read-only access to all tenant data |

## 🔄 Message Flow

1. **Outbound**: API → Message Queue → WAHA → WhatsApp
2. **Inbound**: WhatsApp → WAHA → Webhook → Database → API
3. **Status**: WhatsApp → WAHA → Webhook → Database Update

## 🐳 Docker Deployment

### Development
```bash
docker-compose up -d
```

### Production
```bash
docker-compose -f docker-compose.prod.yml up -d
```

## 🧪 Testing

```bash
# Unit tests
npm run test

# Integration tests
npm run test:e2e

# Test coverage
npm run test:cov

# Test specific module
npm run test -- users

# All tests
npm run test:all

# Security tests
npm run test:security

# Database tests
npm run test:database
```

## 📊 Monitoring & Health

- `GET /health` - API health status
- `GET /health/db` - Database connection
- `GET /ready` - System readiness
- `GET /metrics` - Prometheus metrics

## 🔒 Security Considerations

- Change all default secrets in production
- Use strong database passwords
- Enable SSL/TLS for production
- Regular security updates
- Monitor failed login attempts
- Implement request logging
- Use environment variables for secrets

## 🐛 Troubleshooting

### Common Issues

#### WAHA Connection Failed
- Check WAHA container is running: `docker-compose ps`
- Verify `WAHA_BASE_URL` in environment
- Check WAHA API key validity

#### Database Connection Error
- Ensure PostgreSQL is running
- Check `DATABASE_URL` format
- Run migrations: `npm run typeorm:migration:run`

#### Authentication Issues
- Verify JWT secrets are set
- Check token expiration
- Ensure user exists and is active

### Debug Mode
```bash
LOG_LEVEL=debug npm run start:dev
```

## 📈 Performance Tuning

- Database connection pooling configured
- Redis caching for frequent queries
- Message queuing for bulk operations
- Rate limiting to prevent abuse
- Optimized database indexes

## 🔄 CI/CD Pipeline

GitHub Actions configured for:
- Automated testing on PR
- Code quality checks
- Security vulnerability scanning
- Docker image building
- Deployment automation

## 📞 Support

- **Technical Issues**: Create GitHub issue
- **Security Concerns**: Contact security@company.com
- **Documentation**: Check `/docs` folder
- **API Questions**: Review Swagger docs

## 📄 License

MIT License - see LICENSE file for details

---

## Additional Documentation Files

- [API_GUIDE.md](./docs/API_GUIDE.md) - Detailed API usage examples
- [DEPLOYMENT_GUIDE.md](./docs/DEPLOYMENT_GUIDE.md) - Production deployment instructions
- [SECURITY_GUIDE.md](./docs/SECURITY_GUIDE.md) - Security best practices
- [TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md) - Common issues and solutions
- [CHANGELOG.md](./CHANGELOG.md) - Version history and changes

## Final Checklist Validation

Run through this checklist to ensure everything is working:

- [ ] Docker compose starts all services
- [ ] Database migrations run successfully
- [ ] Swagger documentation loads at `/api/docs`
- [ ] Authentication flow works (login/refresh/logout)
- [ ] User can create WAHA session and get QR code
- [ ] Message sending works end-to-end
- [ ] Webhook receives inbound messages
- [ ] All tests pass with >90% coverage
- [ ] Tenant isolation prevents cross-tenant access
- [ ] RBAC properly restricts access by role
- [ ] Rate limiting works on auth endpoints
- [ ] Health checks return proper status
- [ ] Postman collection works for all endpoints

## Project Status: ✅ Production Ready

The multi-tenant messaging microservice is now complete with all requirements implemented, documented, and tested.