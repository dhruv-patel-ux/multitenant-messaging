# Troubleshooting Guide

This guide helps diagnose and resolve common issues with the Multi-Tenant Messaging API.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Authentication Issues](#authentication-issues)
3. [Database Problems](#database-problems)
4. [WAHA Integration Issues](#waha-integration-issues)
5. [Message Delivery Problems](#message-delivery-problems)
6. [Performance Issues](#performance-issues)
7. [Security Issues](#security-issues)
8. [Deployment Issues](#deployment-issues)
9. [Monitoring and Logs](#monitoring-and-logs)
10. [Emergency Procedures](#emergency-procedures)

## Quick Diagnostics

### Health Check Commands

```bash
# Check API health
curl http://localhost:3000/health

# Check database connection
curl http://localhost:3000/health/db

# Check WAHA service
curl http://localhost:3000/waha/health

# Check system resources
htop
df -h
free -h
```

### Service Status

```bash
# Check Docker services
docker-compose ps

# Check PM2 processes
pm2 status

# Check system services
sudo systemctl status postgresql
sudo systemctl status redis
sudo systemctl status nginx
```

## Authentication Issues

### Problem: Login Fails with "Invalid Credentials"

**Symptoms:**
- 401 Unauthorized response
- "Invalid credentials" error message

**Diagnosis:**
```bash
# Check user exists
psql -U messaging_user -d multitenant_messaging -c "SELECT email, is_active FROM users WHERE email = 'user@example.com';"

# Check password hash
psql -U messaging_user -d multitenant_messaging -c "SELECT password_hash FROM users WHERE email = 'user@example.com';"

# Check tenant status
psql -U messaging_user -d multitenant_messaging -c "SELECT id, name, status FROM tenants WHERE id = 'tenant-id';"
```

**Solutions:**
1. **User doesn't exist:**
   ```bash
   # Create user
   npm run seed:user -- --email=user@example.com --password=password123 --role=TENANT_ADMIN
   ```

2. **User is inactive:**
   ```sql
   UPDATE users SET is_active = true WHERE email = 'user@example.com';
   ```

3. **Tenant is inactive:**
   ```sql
   UPDATE tenants SET status = 'active' WHERE id = 'tenant-id';
   ```

4. **Password mismatch:**
   ```bash
   # Reset password
   npm run reset-password -- --email=user@example.com --password=newpassword123
   ```

### Problem: JWT Token Expired

**Symptoms:**
- 401 Unauthorized response
- "Token expired" error message

**Solutions:**
1. **Refresh token:**
   ```bash
   curl -X POST http://localhost:3000/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken": "your-refresh-token"}'
   ```

2. **Login again:**
   ```bash
   curl -X POST http://localhost:3000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "password123"}'
   ```

### Problem: Rate Limiting on Login

**Symptoms:**
- 429 Too Many Requests
- "Too many login attempts" error

**Solutions:**
1. **Wait for rate limit to reset:**
   ```bash
   # Check rate limit status
   curl -I http://localhost:3000/auth/login
   # Look for X-RateLimit-Reset header
   ```

2. **Clear rate limit (admin only):**
   ```bash
   # Clear Redis rate limit keys
   redis-cli FLUSHDB
   ```

3. **Reset login attempts:**
   ```sql
   DELETE FROM login_attempts WHERE email = 'user@example.com';
   ```

## Database Problems

### Problem: Database Connection Failed

**Symptoms:**
- "Database connection failed" error
- Application won't start

**Diagnosis:**
```bash
# Test database connection
psql -h localhost -U messaging_user -d multitenant_messaging -c "SELECT 1;"

# Check PostgreSQL status
sudo systemctl status postgresql

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log
```

**Solutions:**
1. **PostgreSQL not running:**
   ```bash
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   ```

2. **Wrong credentials:**
   ```bash
   # Check environment variables
   echo $DB_HOST $DB_USERNAME $DB_PASSWORD $DB_DATABASE
   ```

3. **Database doesn't exist:**
   ```bash
   # Create database
   sudo -u postgres createdb multitenant_messaging
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE multitenant_messaging TO messaging_user;"
   ```

4. **Connection pool exhausted:**
   ```bash
   # Restart application
   pm2 restart messaging-api
   # Or
   docker-compose restart app
   ```

### Problem: Migration Failed

**Symptoms:**
- "Migration failed" error
- Database schema inconsistencies

**Solutions:**
1. **Run migrations manually:**
   ```bash
   npm run typeorm:migration:run
   ```

2. **Reset migrations:**
   ```bash
   # Drop and recreate database
   sudo -u postgres dropdb multitenant_messaging
   sudo -u postgres createdb multitenant_messaging
   npm run typeorm:migration:run
   ```

3. **Fix specific migration:**
   ```bash
   # Check migration status
   npm run typeorm:migration:show
   
   # Run specific migration
   npm run typeorm:migration:run -- --transaction=each
   ```

### Problem: Slow Database Queries

**Symptoms:**
- High response times
- Database CPU usage high

**Diagnosis:**
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

**Solutions:**
1. **Add database indexes:**
   ```sql
   CREATE INDEX CONCURRENTLY idx_messages_tenant_id ON messages(tenant_id);
   CREATE INDEX CONCURRENTLY idx_messages_created_at ON messages(created_at);
   CREATE INDEX CONCURRENTLY idx_users_email_tenant ON users(email, tenant_id);
   ```

2. **Optimize queries:**
   ```sql
   -- Analyze tables
   ANALYZE messages;
   ANALYZE users;
   ANALYZE tenants;
   ```

3. **Increase connection pool:**
   ```typescript
   // In database config
   extra: {
     max: 50,  // Increase max connections
     min: 10,  // Increase min connections
   }
   ```

## WAHA Integration Issues

### Problem: WAHA Service Unavailable

**Symptoms:**
- "WAHA service unavailable" error
- Session creation fails

**Diagnosis:**
```bash
# Check WAHA service
curl http://localhost:3001/health

# Check WAHA logs
docker-compose logs waha

# Check network connectivity
telnet localhost 3001
```

**Solutions:**
1. **WAHA service not running:**
   ```bash
   # Start WAHA service
   docker-compose up -d waha
   
   # Check WAHA status
   docker-compose ps waha
   ```

2. **Wrong WAHA URL:**
   ```bash
   # Check environment variable
   echo $WAHA_BASE_URL
   
   # Update if needed
   export WAHA_BASE_URL=http://localhost:3001
   ```

3. **WAHA API key invalid:**
   ```bash
   # Check API key
   echo $WAHA_API_KEY
   
   # Test with curl
   curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/health
   ```

### Problem: Session Creation Fails

**Symptoms:**
- "Session creation failed" error
- QR code not generated

**Solutions:**
1. **Check WAHA configuration:**
   ```bash
   # Verify WAHA is running
   curl http://localhost:3001/api/health
   
   # Check WAHA version
   curl http://localhost:3001/api/version
   ```

2. **Clear WAHA sessions:**
   ```bash
   # List sessions
   curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions
   
   # Delete old sessions
   curl -X DELETE -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/old-session-id
   ```

3. **Restart WAHA service:**
   ```bash
   docker-compose restart waha
   ```

### Problem: QR Code Not Generated

**Symptoms:**
- QR code endpoint returns empty
- Session stuck in "scan_qr" state

**Solutions:**
1. **Check session status:**
   ```bash
   curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id
   ```

2. **Regenerate QR code:**
   ```bash
   # Stop and restart session
   curl -X POST -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id/stop
   curl -X POST -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id/start
   ```

3. **Check WAHA logs:**
   ```bash
   docker-compose logs waha | grep -i qr
   ```

## Message Delivery Problems

### Problem: Messages Not Sending

**Symptoms:**
- Messages stuck in "queued" status
- No delivery confirmations

**Diagnosis:**
```bash
# Check message status
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/messages?status=queued

# Check WAHA session status
curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id
```

**Solutions:**
1. **Session not connected:**
   ```bash
   # Check session status
   curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id
   
   # Restart session if needed
   curl -X POST -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id/start
   ```

2. **Message queue stuck:**
   ```bash
   # Process message queue
   npm run process-queue
   
   # Or restart application
   pm2 restart messaging-api
   ```

3. **Rate limiting:**
   ```bash
   # Check rate limit status
   curl -I -H "Authorization: Bearer $TOKEN" http://localhost:3000/messages/send
   ```

### Problem: Inbound Messages Not Received

**Symptoms:**
- Webhook not receiving messages
- Inbound messages not stored

**Solutions:**
1. **Check webhook configuration:**
   ```bash
   # Verify webhook URL is accessible
   curl -X POST https://your-domain.com/webhooks/waha \
     -H "Content-Type: application/json" \
     -d '{"test": "webhook"}'
   ```

2. **Check webhook signature:**
   ```bash
   # Verify webhook secret
   echo $WEBHOOK_SECRET
   ```

3. **Check webhook logs:**
   ```bash
   # Check application logs
   pm2 logs messaging-api | grep webhook
   
   # Or Docker logs
   docker-compose logs app | grep webhook
   ```

### Problem: Message Status Not Updating

**Symptoms:**
- Messages stuck in "sent" status
- No delivery confirmations

**Solutions:**
1. **Check webhook processing:**
   ```bash
   # Check webhook endpoint
   curl http://localhost:3000/webhooks/health
   ```

2. **Process status updates:**
   ```bash
   # Manually process status updates
   npm run process-status-updates
   ```

3. **Check WAHA webhook configuration:**
   ```bash
   # Verify WAHA webhook URL
   curl -H "Authorization: Bearer $WAHA_API_KEY" http://localhost:3001/api/sessions/session-id
   ```

## Performance Issues

### Problem: High Response Times

**Symptoms:**
- API responses > 2 seconds
- High CPU usage

**Diagnosis:**
```bash
# Check system resources
htop
iostat -x 1
netstat -tulpn | grep :3000

# Check database performance
psql -U messaging_user -d multitenant_messaging -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"
```

**Solutions:**
1. **Optimize database queries:**
   ```sql
   -- Add missing indexes
   CREATE INDEX CONCURRENTLY idx_messages_tenant_status ON messages(tenant_id, status);
   CREATE INDEX CONCURRENTLY idx_users_tenant_active ON users(tenant_id, is_active);
   ```

2. **Increase connection pool:**
   ```typescript
   // In database config
   extra: {
     max: 100,  // Increase max connections
     min: 20,   // Increase min connections
   }
   ```

3. **Enable Redis caching:**
   ```bash
   # Start Redis
   docker-compose up -d redis
   
   # Configure caching in application
   export REDIS_HOST=localhost
   export REDIS_PORT=6379
   ```

### Problem: Memory Issues

**Symptoms:**
- High memory usage
- Out of memory errors

**Solutions:**
1. **Optimize memory usage:**
   ```bash
   # Check memory usage
   free -h
   ps aux --sort=-%mem | head -10
   ```

2. **Restart services:**
   ```bash
   # Restart application
   pm2 restart messaging-api
   
   # Or Docker
   docker-compose restart app
   ```

3. **Increase memory limits:**
   ```bash
   # For Docker
   docker-compose up -d --scale app=2
   ```

### Problem: Database Connection Pool Exhausted

**Symptoms:**
- "Connection pool exhausted" error
- Database connection timeouts

**Solutions:**
1. **Increase connection pool:**
   ```typescript
   // In database config
   extra: {
     max: 50,  // Increase max connections
     min: 10,  // Increase min connections
     acquireTimeoutMillis: 60000,
     idleTimeoutMillis: 30000,
   }
   ```

2. **Check for connection leaks:**
   ```sql
   -- Check active connections
   SELECT count(*) FROM pg_stat_activity WHERE state = 'active';
   
   -- Check connection limits
   SHOW max_connections;
   ```

3. **Restart database:**
   ```bash
   sudo systemctl restart postgresql
   ```

## Security Issues

### Problem: Unauthorized Access Attempts

**Symptoms:**
- Multiple failed login attempts
- Suspicious activity in logs

**Solutions:**
1. **Block IP addresses:**
   ```bash
   # Block IP using iptables
   sudo iptables -A INPUT -s 192.168.1.100 -j DROP
   
   # Or using fail2ban
   sudo fail2ban-client set messaging-api banip 192.168.1.100
   ```

2. **Review security logs:**
   ```bash
   # Check security logs
   grep "SECURITY" /var/log/messaging-api.log
   
   # Check failed login attempts
   psql -U messaging_user -d multitenant_messaging -c "SELECT * FROM login_attempts WHERE is_successful = false ORDER BY created_at DESC LIMIT 10;"
   ```

3. **Implement additional security:**
   ```bash
   # Enable fail2ban
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

### Problem: Data Breach Suspected

**Symptoms:**
- Unusual data access patterns
- Security alerts triggered

**Emergency Response:**
1. **Immediate actions:**
   ```bash
   # Lock all user accounts
   psql -U messaging_user -d multitenant_messaging -c "UPDATE users SET is_active = false;"
   
   # Revoke all sessions
   psql -U messaging_user -d multitenant_messaging -c "UPDATE refresh_tokens SET is_revoked = true;"
   
   # Block suspicious IPs
   sudo iptables -A INPUT -s suspicious-ip -j DROP
   ```

2. **Investigation:**
   ```bash
   # Check access logs
   grep "suspicious-ip" /var/log/nginx/access.log
   
   # Check database access
   psql -U messaging_user -d multitenant_messaging -c "SELECT * FROM security_audit_log WHERE ip_address = 'suspicious-ip' ORDER BY created_at DESC;"
   ```

3. **Recovery:**
   ```bash
   # Restore from backup
   pg_restore -U messaging_user -d multitenant_messaging /opt/backups/db_backup.sql
   
   # Reset all passwords
   npm run reset-all-passwords
   ```

## Deployment Issues

### Problem: Application Won't Start

**Symptoms:**
- Application fails to start
- Port already in use

**Solutions:**
1. **Check port availability:**
   ```bash
   # Check if port is in use
   netstat -tulpn | grep :3000
   
   # Kill process using port
   sudo kill -9 $(lsof -t -i:3000)
   ```

2. **Check environment variables:**
   ```bash
   # Verify required environment variables
   env | grep -E "(DB_|JWT_|WAHA_)"
   ```

3. **Check dependencies:**
   ```bash
   # Install dependencies
   npm install
   
   # Check Node.js version
   node --version
   ```

### Problem: Docker Build Fails

**Symptoms:**
- Docker build errors
- Image creation fails

**Solutions:**
1. **Check Dockerfile:**
   ```bash
   # Build with verbose output
   docker build --no-cache -t messaging-api .
   ```

2. **Check Docker resources:**
   ```bash
   # Check Docker disk space
   docker system df
   
   # Clean up Docker
   docker system prune -a
   ```

3. **Check Docker daemon:**
   ```bash
   # Restart Docker
   sudo systemctl restart docker
   ```

## Monitoring and Logs

### Log Locations

```bash
# Application logs
pm2 logs messaging-api
docker-compose logs app

# Database logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# System logs
sudo tail -f /var/log/syslog
```

### Monitoring Commands

```bash
# Check system resources
htop
iotop
nethogs

# Check database performance
psql -U messaging_user -d multitenant_messaging -c "SELECT * FROM pg_stat_activity;"

# Check application metrics
curl http://localhost:3000/metrics
```

### Log Analysis

```bash
# Search for errors
grep -i error /var/log/messaging-api.log

# Search for security events
grep -i security /var/log/messaging-api.log

# Analyze access patterns
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr
```

## Emergency Procedures

### Complete System Recovery

```bash
# 1. Stop all services
docker-compose down
pm2 stop all

# 2. Restore database
pg_restore -U messaging_user -d multitenant_messaging /opt/backups/latest_backup.sql

# 3. Restore application
tar -xzf /opt/backups/latest_app_backup.tar.gz -C /opt/

# 4. Restart services
docker-compose up -d
pm2 start all

# 5. Verify functionality
curl http://localhost:3000/health
```

### Data Recovery

```bash
# 1. Stop application
pm2 stop messaging-api

# 2. Restore database
sudo -u postgres psql -c "DROP DATABASE multitenant_messaging;"
sudo -u postgres psql -c "CREATE DATABASE multitenant_messaging;"
pg_restore -U messaging_user -d multitenant_messaging /opt/backups/db_backup.sql

# 3. Restart application
pm2 start messaging-api
```

### Security Incident Response

```bash
# 1. Isolate system
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP

# 2. Preserve evidence
sudo cp /var/log/messaging-api.log /opt/evidence/
sudo cp /var/log/nginx/access.log /opt/evidence/

# 3. Notify security team
echo "Security incident detected" | mail -s "URGENT: Security Incident" security@company.com

# 4. Begin investigation
grep -i "suspicious" /var/log/messaging-api.log
```

This troubleshooting guide provides comprehensive solutions for common issues. For additional support, refer to the security guide and deployment documentation.
