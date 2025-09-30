# Security Guide

This guide covers security best practices and considerations for the Multi-Tenant Messaging API.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication Security](#authentication-security)
3. [Authorization Security](#authorization-security)
4. [Data Protection](#data-protection)
5. [Network Security](#network-security)
6. [Application Security](#application-security)
7. [Infrastructure Security](#infrastructure-security)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Incident Response](#incident-response)
10. [Security Checklist](#security-checklist)

## Security Overview

The Multi-Tenant Messaging API implements multiple layers of security to protect against common threats and ensure data isolation between tenants.

### Security Layers

1. **Authentication**: JWT-based authentication with refresh tokens
2. **Authorization**: Role-based access control (RBAC)
3. **Data Isolation**: Tenant-level data segregation
4. **Input Validation**: Comprehensive input sanitization
5. **Rate Limiting**: Protection against abuse
6. **Encryption**: Data encryption in transit and at rest
7. **Audit Logging**: Security event tracking

## Authentication Security

### 1. Password Security

```typescript
// Strong password requirements
const passwordValidation = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true
};

// Password hashing with bcrypt
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(password, saltRounds);
```

### 2. JWT Security

```typescript
// JWT configuration
const jwtConfig = {
  accessTokenExpiry: '15m',      // Short-lived access tokens
  refreshTokenExpiry: '7d',      // Longer-lived refresh tokens
  algorithm: 'HS256',            // Secure algorithm
  issuer: 'messaging-api',       // Token issuer
  audience: 'messaging-clients'  // Token audience
};

// Token validation
const validateToken = (token: string) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'messaging-api',
      audience: 'messaging-clients'
    });
  } catch (error) {
    throw new UnauthorizedException('Invalid token');
  }
};
```

### 3. Session Management

```typescript
// Secure session handling
class SessionManager {
  async createSession(userId: string, ipAddress: string, userAgent: string) {
    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await this.sessionRepository.save({
      id: sessionId,
      userId,
      ipAddress,
      userAgent,
      expiresAt,
      isActive: true
    });
    
    return sessionId;
  }
  
  async invalidateSession(sessionId: string) {
    await this.sessionRepository.update(sessionId, {
      isActive: false,
      revokedAt: new Date()
    });
  }
  
  async invalidateAllUserSessions(userId: string) {
    await this.sessionRepository.update(
      { userId, isActive: true },
      { isActive: false, revokedAt: new Date() }
    );
  }
}
```

## Authorization Security

### 1. Role-Based Access Control

```typescript
// Permission-based authorization
@Injectable()
export class RoleGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (!requiredRoles) return true;
    
    const { user } = context.switchToHttp().getRequest();
    const userRole = user.role as UserRole;
    
    // Check role hierarchy
    return this.hasRequiredRole(userRole, requiredRoles);
  }
  
  private hasRequiredRole(userRole: UserRole, requiredRoles: UserRole[]): boolean {
    return requiredRoles.some(role => {
      return userRole === role || 
             HIERARCHICAL_ROLES[userRole]?.includes(role);
    });
  }
}
```

### 2. Resource-Level Authorization

```typescript
// Tenant isolation enforcement
@Injectable()
export class TenantGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    if (!user || !user.tenantId) {
      throw new ForbiddenException('Tenant context required');
    }
    
    // Validate tenant exists and is active
    const tenant = await this.tenantRepository.findOne({
      where: { id: user.tenantId, status: TenantStatus.ACTIVE }
    });
    
    if (!tenant) {
      throw new ForbiddenException('Invalid tenant');
    }
    
    // Attach tenant context to request
    request.tenant = tenant;
    return true;
  }
}
```

## Data Protection

### 1. Data Encryption

```typescript
// Encrypt sensitive data
import * as crypto from 'crypto';

class DataEncryption {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
  
  encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, this.key);
    cipher.setAAD(Buffer.from('messaging-api', 'utf8'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }
  
  decrypt(encryptedData: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    const decipher = crypto.createDecipher(this.algorithm, this.key);
    decipher.setAAD(Buffer.from('messaging-api', 'utf8'));
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

### 2. PII Protection

```typescript
// PII detection and masking
class PIIProtection {
  private readonly piiPatterns = {
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /\b\+?[1-9]\d{1,14}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g
  };
  
  detectPII(text: string): string[] {
    const detectedPII: string[] = [];
    
    Object.entries(this.piiPatterns).forEach(([type, pattern]) => {
      const matches = text.match(pattern);
      if (matches) {
        detectedPII.push(...matches.map(match => `${type}:${match}`));
      }
    });
    
    return detectedPII;
  }
  
  maskPII(text: string): string {
    let maskedText = text;
    
    Object.values(this.piiPatterns).forEach(pattern => {
      maskedText = maskedText.replace(pattern, '***MASKED***');
    });
    
    return maskedText;
  }
}
```

## Network Security

### 1. HTTPS Configuration

```typescript
// HTTPS enforcement
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

### 2. CORS Configuration

```typescript
// Secure CORS configuration
app.enableCors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.CORS_ORIGINS?.split(',') || [];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining']
});
```

### 3. Rate Limiting

```typescript
// Advanced rate limiting
@Injectable()
export class RateLimitService {
  private readonly limits = {
    login: { max: 5, window: 15 * 60 * 1000 },      // 5 attempts per 15 minutes
    api: { max: 100, window: 60 * 1000 },           // 100 requests per minute
    messages: { max: 20, window: 60 * 1000 },      // 20 messages per minute
    webhooks: { max: 50, window: 60 * 1000 }        // 50 webhooks per minute
  };
  
  async checkRateLimit(
    identifier: string, 
    type: keyof typeof this.limits
  ): Promise<boolean> {
    const limit = this.limits[type];
    const key = `rate_limit:${type}:${identifier}`;
    
    const current = await this.redis.get(key);
    if (current && parseInt(current) >= limit.max) {
      return false;
    }
    
    await this.redis.incr(key);
    await this.redis.expire(key, Math.ceil(limit.window / 1000));
    
    return true;
  }
}
```

## Application Security

### 1. Input Validation

```typescript
// Comprehensive input validation
export class InputValidationService {
  validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
  }
  
  validatePhoneNumber(phone: string): boolean {
    const phoneRegex = /^\+[1-9]\d{1,14}$/;
    return phoneRegex.test(phone);
  }
  
  sanitizeInput(input: string): string {
    return input
      .replace(/[<>]/g, '')           // Remove HTML tags
      .replace(/javascript:/gi, '')   // Remove javascript: protocol
      .replace(/on\w+=/gi, '')       // Remove event handlers
      .trim();
  }
  
  validateUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }
}
```

### 2. SQL Injection Prevention

```typescript
// TypeORM query security
@Injectable()
export class SecureQueryService {
  async findUserByEmail(email: string, tenantId: string): Promise<User | null> {
    // Use parameterized queries
    return this.userRepository.findOne({
      where: { 
        email: email,           // TypeORM automatically escapes parameters
        tenantId: tenantId 
      }
    });
  }
  
  async searchMessages(searchTerm: string, tenantId: string): Promise<Message[]> {
    // Use query builder for complex queries
    return this.messageRepository
      .createQueryBuilder('message')
      .where('message.tenantId = :tenantId', { tenantId })
      .andWhere('message.body ILIKE :searchTerm', { 
        searchTerm: `%${searchTerm}%` 
      })
      .getMany();
  }
}
```

### 3. XSS Prevention

```typescript
// XSS protection middleware
@Injectable()
export class XSSProtectionMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Sanitize request body
    if (req.body) {
      req.body = this.sanitizeObject(req.body);
    }
    
    // Sanitize query parameters
    if (req.query) {
      req.query = this.sanitizeObject(req.query);
    }
    
    next();
  }
  
  private sanitizeObject(obj: any): any {
    if (typeof obj === 'string') {
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '');
    }
    
    if (typeof obj === 'object' && obj !== null) {
      const sanitized: any = {};
      for (const key in obj) {
        sanitized[key] = this.sanitizeObject(obj[key]);
      }
      return sanitized;
    }
    
    return obj;
  }
}
```

## Infrastructure Security

### 1. Database Security

```sql
-- Database user permissions
CREATE USER messaging_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE multitenant_messaging TO messaging_user;
GRANT USAGE ON SCHEMA public TO messaging_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO messaging_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO messaging_user;

-- Row-level security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
  FOR ALL TO messaging_user
  USING (tenant_id = current_setting('app.current_tenant_id'));
```

### 2. Environment Security

```bash
# Secure environment file
chmod 600 .env.production
chown root:root .env.production

# Environment variable validation
const requiredEnvVars = [
  'JWT_SECRET',
  'DB_PASSWORD',
  'WAHA_API_KEY',
  'WEBHOOK_SECRET'
];

requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
});
```

### 3. Container Security

```dockerfile
# Security-hardened Dockerfile
FROM node:20-alpine AS production

# Install security updates
RUN apk update && apk upgrade

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Set secure file permissions
RUN chown -R nestjs:nodejs /app
USER nestjs

# Remove unnecessary packages
RUN apk del --purge

# Use read-only filesystem where possible
VOLUME ["/app/logs"]
```

## Monitoring and Logging

### 1. Security Event Logging

```typescript
// Security audit logging
@Injectable()
export class SecurityAuditService {
  async logSecurityEvent(event: SecurityEvent): Promise<void> {
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType: event.eventType,
      userId: event.userId,
      tenantId: event.tenantId,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      resource: event.resource,
      action: event.action,
      severity: event.severity,
      details: event.details
    };
    
    // Log to secure audit log
    await this.auditLogger.log(logEntry);
    
    // Alert on critical events
    if (event.severity === 'Critical') {
      await this.alertService.sendAlert(logEntry);
    }
  }
}
```

### 2. Intrusion Detection

```typescript
// Suspicious activity detection
@Injectable()
export class IntrusionDetectionService {
  async detectSuspiciousActivity(
    userId: string, 
    ipAddress: string, 
    action: string
  ): Promise<boolean> {
    const recentActions = await this.getRecentActions(userId, ipAddress);
    
    // Detect brute force attempts
    if (this.detectBruteForce(recentActions)) {
      await this.lockAccount(userId);
      return true;
    }
    
    // Detect unusual access patterns
    if (this.detectUnusualPatterns(recentActions)) {
      await this.alertSecurityTeam(userId, ipAddress, action);
      return true;
    }
    
    return false;
  }
}
```

## Incident Response

### 1. Security Incident Response Plan

```typescript
// Incident response automation
@Injectable()
export class IncidentResponseService {
  async handleSecurityIncident(incident: SecurityIncident): Promise<void> {
    // Immediate response
    if (incident.severity === 'Critical') {
      await this.isolateAffectedSystems(incident);
      await this.notifySecurityTeam(incident);
    }
    
    // Evidence collection
    await this.collectEvidence(incident);
    
    // Forensic analysis
    await this.performForensicAnalysis(incident);
    
    // Recovery procedures
    await this.executeRecoveryProcedures(incident);
  }
}
```

### 2. Automated Response

```typescript
// Automated security responses
class AutomatedResponseService {
  async handleFailedLoginAttempt(email: string, ipAddress: string): Promise<void> {
    const attemptCount = await this.getFailedAttemptCount(email, ipAddress);
    
    if (attemptCount >= 5) {
      // Lock account
      await this.lockAccount(email);
      
      // Block IP address
      await this.blockIPAddress(ipAddress);
      
      // Notify security team
      await this.notifySecurityTeam({
        type: 'BRUTE_FORCE_ATTEMPT',
        email,
        ipAddress,
        attemptCount
      });
    }
  }
}
```

## Security Checklist

### Pre-Deployment Security Checklist

- [ ] **Authentication**
  - [ ] Strong password requirements enforced
  - [ ] JWT secrets are cryptographically secure
  - [ ] Refresh token rotation implemented
  - [ ] Session management properly configured

- [ ] **Authorization**
  - [ ] RBAC properly implemented
  - [ ] Tenant isolation enforced
  - [ ] Resource-level permissions configured
  - [ ] Privilege escalation prevented

- [ ] **Data Protection**
  - [ ] Sensitive data encrypted at rest
  - [ ] PII detection and masking implemented
  - [ ] Database connections encrypted
  - [ ] Backup encryption configured

- [ ] **Network Security**
  - [ ] HTTPS enforced
  - [ ] Security headers configured
  - [ ] CORS properly configured
  - [ ] Rate limiting implemented

- [ ] **Application Security**
  - [ ] Input validation comprehensive
  - [ ] SQL injection prevention
  - [ ] XSS protection enabled
  - [ ] CSRF protection configured

- [ ] **Infrastructure Security**
  - [ ] Database security hardened
  - [ ] Environment variables secured
  - [ ] Container security implemented
  - [ ] Network segmentation configured

- [ ] **Monitoring**
  - [ ] Security event logging enabled
  - [ ] Intrusion detection configured
  - [ ] Alerting system operational
  - [ ] Audit trail maintained

### Regular Security Maintenance

- [ ] **Weekly**
  - [ ] Review security logs
  - [ ] Check for failed login attempts
  - [ ] Monitor unusual activity patterns
  - [ ] Verify backup integrity

- [ ] **Monthly**
  - [ ] Security vulnerability assessment
  - [ ] Access review and cleanup
  - [ ] Security policy updates
  - [ ] Incident response testing

- [ ] **Quarterly**
  - [ ] Penetration testing
  - [ ] Security training updates
  - [ ] Disaster recovery testing
  - [ ] Compliance audit

This security guide provides comprehensive coverage of security considerations for the Multi-Tenant Messaging API. Regular review and updates of security measures are essential to maintain a secure production environment.
