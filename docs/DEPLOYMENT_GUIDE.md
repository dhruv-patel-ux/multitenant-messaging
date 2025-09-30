# Deployment Guide

This guide covers production deployment of the Multi-Tenant Messaging API.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Docker Deployment](#docker-deployment)
4. [Manual Deployment](#manual-deployment)
5. [Database Setup](#database-setup)
6. [SSL/TLS Configuration](#ssltls-configuration)
7. [Monitoring Setup](#monitoring-setup)
8. [Backup Strategy](#backup-strategy)
9. [Scaling Considerations](#scaling-considerations)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **OS**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- **CPU**: 2+ cores
- **RAM**: 4GB+ (8GB+ recommended)
- **Storage**: 50GB+ SSD
- **Network**: Stable internet connection

### Software Requirements

- **Node.js**: 18.x or 20.x
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **PostgreSQL**: 15+
- **Redis**: 6.0+ (optional, for caching)
- **Nginx**: 1.18+ (for reverse proxy)

## Environment Setup

### 1. Create Production Environment File

```bash
# Create production environment file
cp .env.example .env.production
```

### 2. Configure Environment Variables

```bash
# .env.production
NODE_ENV=production
PORT=3000

# Database Configuration
DB_HOST=your-db-host
DB_PORT=5432
DB_USERNAME=your-db-user
DB_PASSWORD=your-secure-password
DB_DATABASE=multitenant_messaging

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRES_IN=900
JWT_REFRESH_EXPIRES_IN=604800

# WAHA Configuration
WAHA_BASE_URL=http://[::1]:3000/
WAHA_API_KEY=wahaintegrationapikey009908
WAHA_TIMEOUT=30000

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_MAX=1000
RATE_LIMIT_WINDOW=60000

# CORS Configuration
CORS_ORIGIN=https://your-frontend-domain.com

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json

# Redis Configuration (optional)
REDIS_HOST=your-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# Webhook Configuration
WEBHOOK_SECRET=your-webhook-secret-key
```

### 3. Security Considerations

```bash
# Generate secure secrets
openssl rand -base64 32  # For JWT_SECRET
openssl rand -base64 32  # For WEBHOOK_SECRET
openssl rand -base64 32  # For DB_PASSWORD
```

## Docker Deployment

### 1. Create Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.prod
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs
    networks:
      - messaging-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: multitenant_messaging
      POSTGRES_USER: ${DB_USERNAME}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    ports:
      - "5432:5432"
    restart: unless-stopped
    networks:
      - messaging-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - messaging-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - messaging-network

volumes:
  postgres_data:
  redis_data:

networks:
  messaging-network:
    driver: bridge
```

### 2. Create Production Dockerfile

```dockerfile
# Dockerfile.prod
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Copy built application
COPY --from=builder --chown=nestjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nestjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nestjs:nodejs /app/package*.json ./

# Switch to non-root user
USER nestjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/health-check.js

# Start application
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
```

### 3. Deploy with Docker

```bash
# Build and start services
docker-compose -f docker-compose.prod.yml up -d

# Run database migrations
docker-compose -f docker-compose.prod.yml exec app npm run typeorm:migration:run

# Check service status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f app
```

## Manual Deployment

### 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Install Redis
sudo apt install redis-server -y

# Install Nginx
sudo apt install nginx -y

# Install PM2 for process management
sudo npm install -g pm2
```

### 2. Application Deployment

```bash
# Clone repository
git clone <repository-url> /opt/multitenant-messaging-api
cd /opt/multitenant-messaging-api

# Install dependencies
npm ci --only=production

# Build application
npm run build

# Set up environment
cp .env.example .env.production
# Edit .env.production with your settings

# Run migrations
npm run typeorm:migration:run

# Start with PM2
pm2 start dist/main.js --name "messaging-api"
pm2 save
pm2 startup
```

## Database Setup

### 1. PostgreSQL Configuration

```bash
# Create database and user
sudo -u postgres psql

CREATE DATABASE multitenant_messaging;
CREATE USER messaging_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE multitenant_messaging TO messaging_user;
\q
```

### 2. Database Optimization

```sql
-- postgresql.conf optimizations
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
```

### 3. Database Backup

```bash
# Create backup script
cat > /opt/backup-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h localhost -U messaging_user multitenant_messaging > $BACKUP_DIR/messaging_$DATE.sql
find $BACKUP_DIR -name "messaging_*.sql" -mtime +7 -delete
EOF

chmod +x /opt/backup-db.sh

# Add to crontab
echo "0 2 * * * /opt/backup-db.sh" | crontab -
```

## SSL/TLS Configuration

### 1. Obtain SSL Certificate

```bash
# Using Let's Encrypt
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

### 2. Nginx Configuration

```nginx
# /etc/nginx/sites-available/messaging-api
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Authentication endpoints
    location /api/auth/ {
        limit_req zone=auth burst=10 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Webhook endpoints
    location /webhooks/ {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check
    location /health {
        proxy_pass http://localhost:3000;
        access_log off;
    }
}
```

## Monitoring Setup

### 1. Application Monitoring

```bash
# Install monitoring tools
sudo apt install htop iotop nethogs -y

# Set up log rotation
sudo cat > /etc/logrotate.d/messaging-api << 'EOF'
/opt/multitenant-messaging-api/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 nestjs nestjs
}
EOF
```

### 2. PM2 Monitoring

```bash
# Install PM2 monitoring
pm2 install pm2-logrotate
pm2 install pm2-server-monit

# Configure monitoring
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
pm2 set pm2-logrotate:compress true
```

### 3. Health Checks

```bash
# Create health check script
cat > /opt/health-check.sh << 'EOF'
#!/bin/bash
HEALTH_URL="http://localhost:3000/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy (HTTP $RESPONSE)"
    exit 1
fi
EOF

chmod +x /opt/health-check.sh

# Add to crontab
echo "*/5 * * * * /opt/health-check.sh" | crontab -
```

## Backup Strategy

### 1. Database Backups

```bash
# Automated database backup
cat > /opt/backup-strategy.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
pg_dump -h localhost -U messaging_user multitenant_messaging | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Application backup
tar -czf $BACKUP_DIR/app_$DATE.tar.gz /opt/multitenant-messaging-api

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
EOF

chmod +x /opt/backup-strategy.sh
```

### 2. Backup Verification

```bash
# Test backup restoration
pg_restore --list /opt/backups/db_$(date +%Y%m%d)_*.sql.gz
```

## Scaling Considerations

### 1. Horizontal Scaling

```yaml
# docker-compose.scale.yml
version: '3.8'

services:
  app:
    build: .
    deploy:
      replicas: 3
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    networks:
      - messaging-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-load-balancer.conf:/etc/nginx/nginx.conf
    depends_on:
      - app
    networks:
      - messaging-network
```

### 2. Load Balancer Configuration

```nginx
# nginx-load-balancer.conf
upstream messaging_api {
    server app_1:3000;
    server app_2:3000;
    server app_3:3000;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://messaging_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

### 1. Common Issues

#### Service Won't Start
```bash
# Check logs
pm2 logs messaging-api
docker-compose logs app

# Check port availability
netstat -tlnp | grep :3000
```

#### Database Connection Issues
```bash
# Test database connection
psql -h localhost -U messaging_user -d multitenant_messaging

# Check PostgreSQL status
sudo systemctl status postgresql
```

#### Memory Issues
```bash
# Check memory usage
free -h
htop

# Restart services if needed
pm2 restart messaging-api
```

### 2. Performance Optimization

```bash
# Database optimization
sudo -u postgres psql -d multitenant_messaging -c "VACUUM ANALYZE;"

# Application optimization
pm2 restart messaging-api
```

### 3. Security Hardening

```bash
# Firewall configuration
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Disable unnecessary services
sudo systemctl disable apache2
sudo systemctl disable mysql
```

This deployment guide provides comprehensive instructions for deploying the Multi-Tenant Messaging API in production environments. Always test deployments in staging environments first and maintain proper backups.
