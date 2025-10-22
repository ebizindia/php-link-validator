# Security Configuration Guide

## Quick Start Security Checklist

Before deploying this application to production, complete the following steps:

### ✅ Essential Configuration

1. **Enable HTTPS on your web server** (Apache/Nginx)
   - SSL certificate required for secure cookies
   - Use Let's Encrypt for free certificates

2. **Update Email Configuration** in `index.php`:
   ```php
   define('EMAIL_FROM', 'your-noreply@yourdomain.com');
   define('EMAIL_TO', 'your-admin@yourdomain.com');
   ```

3. **Verify Security Settings** (lines 49-54 in index.php):
   ```php
   define('ENABLE_SSL_VERIFY', true);        // ✅ Must be true
   define('ENABLE_SSRF_PROTECTION', true);   // ✅ Must be true
   define('RATE_LIMIT_SECONDS', 60);         // ✅ Recommended: 60
   ```

4. **Test CSRF Protection**:
   - Load the form in your browser
   - View page source and confirm CSRF token is present
   - Submit form and verify it works

5. **Test Security Headers**:
   - Visit https://securityheaders.com
   - Enter your domain
   - Should see A or A+ rating

---

## Advanced Configuration

### Adjusting Rate Limits

For public-facing deployments with many users:
```php
define('RATE_LIMIT_SECONDS', 120);  // 2 minutes between checks
```

For internal/trusted networks:
```php
define('RATE_LIMIT_SECONDS', 30);   // 30 seconds between checks
```

### Adjusting Crawl Limits

For resource-constrained servers:
```php
define('MAX_PAGES_DEFAULT', 50);    // Default: 50 pages
define('MAX_PAGES_LIMIT', 200);     // Maximum: 200 pages
```

For powerful servers:
```php
define('MAX_PAGES_DEFAULT', 100);   // Default: 100 pages
define('MAX_PAGES_LIMIT', 500);     // Maximum: 500 pages
```

### Disabling SSRF Protection (NOT RECOMMENDED)

Only disable if you need to scan internal networks (trusted environment only):
```php
define('ENABLE_SSRF_PROTECTION', false);  // ⚠️ DANGEROUS
```

**WARNING**: This allows scanning of internal networks. Only use in isolated, trusted environments.

---

## Web Server Configuration

### Apache (.htaccess)

Create or update `.htaccess`:

```apache
# Security Headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# Force HTTPS
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>

# Disable directory listing
Options -Indexes

# Protect sensitive files
<FilesMatch "^\.">
    Order allow,deny
    Deny from all
</FilesMatch>
```

### Nginx

Add to your nginx configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net;" always;

    # PHP Configuration
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param HTTPS on;
        include fastcgi_params;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## PHP Configuration (php.ini)

Recommended PHP settings for security:

```ini
# Security
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

# Session Security
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_only_cookies = 1
session.cookie_samesite = Strict
session.use_strict_mode = 1

# File Uploads (disable if not needed)
file_uploads = Off

# Execution
max_execution_time = 600
memory_limit = 512M

# Input
post_max_size = 8M
max_input_time = 60
```

---

## Firewall Configuration

### UFW (Ubuntu/Debian)

```bash
# Allow HTTPS
sudo ufw allow 443/tcp

# Allow HTTP (for redirect)
sudo ufw allow 80/tcp

# Enable firewall
sudo ufw enable
```

### iptables

```bash
# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow HTTP (for redirect)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

---

## Monitoring & Logging

### Enable Error Logging

In `index.php`, add at the top:

```php
// Production error logging
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php/link-validator-errors.log');
```

### Security Event Logging (Optional)

Add custom logging for security events:

```php
function logSecurityEvent($event, $details) {
    $logFile = '/var/log/php/security-events.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $message = "[$timestamp] [$ip] $event: $details\n";
    error_log($message, 3, $logFile);
}

// Example usage:
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    logSecurityEvent('CSRF_FAILED', 'Invalid token from ' . $_SERVER['HTTP_REFERER']);
    die('CSRF validation failed');
}
```

---

## Testing Your Security Setup

### 1. Test HTTPS

```bash
curl -I https://yourdomain.com
# Should return 200 OK with security headers
```

### 2. Test Security Headers

Visit: https://securityheaders.com/?q=https://yourdomain.com

Expected result: **A** or **A+** rating

### 3. Test SSL/TLS

Visit: https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com

Expected result: **A** or **A+** rating

### 4. Test CSRF Protection

```bash
# This should fail (no CSRF token):
curl -X POST -d "action=check&domain=example.com" https://yourdomain.com/index.php

# This should also fail (wrong token):
curl -X POST -d "csrf_token=invalid&action=check&domain=example.com" https://yourdomain.com/index.php
```

### 5. Test SSRF Protection

Try to submit these domains (should all be blocked):
- `http://127.0.0.1`
- `http://localhost`
- `http://192.168.1.1`
- `http://10.0.0.1`
- `http://169.254.169.254`

### 6. Test Rate Limiting

Submit two requests within 60 seconds. The second should be blocked.

---

## Troubleshooting

### Issue: "CSRF validation failed"

**Solution**:
- Clear browser cookies
- Ensure session is working: `session_start()` is called
- Check if CSRF token is in form HTML source

### Issue: "Invalid or unsafe URL provided"

**Cause**: SSRF protection blocking the domain

**Solution**:
- Verify the domain is not an internal IP
- Check if domain resolves to a public IP
- Temporarily disable SSRF protection for testing (not recommended)

### Issue: Rate limit too strict

**Solution**:
Adjust `RATE_LIMIT_SECONDS` in index.php:
```php
define('RATE_LIMIT_SECONDS', 30);  // Reduce from 60 to 30 seconds
```

### Issue: SSL verification failing

**Cause**: Target website has invalid SSL certificate

**Solution**:
This is working as intended. The tool should not connect to sites with invalid certificates. If you need to scan such sites (not recommended):
```php
define('ENABLE_SSL_VERIFY', false);  // ⚠️ Not recommended
```

---

## Backup & Recovery

### Before Making Changes

Always backup before modifying:

```bash
cp index.php index.php.backup
cp .htaccess .htaccess.backup
```

### Restore Previous Version

```bash
mv index.php.backup index.php
mv .htaccess.backup .htaccess
```

---

## Security Maintenance Schedule

| Task | Frequency | Description |
|------|-----------|-------------|
| Check for PHP updates | Monthly | Update to latest PHP version |
| Review error logs | Weekly | Check for suspicious activity |
| Test security headers | Monthly | Verify headers are still active |
| Review SSL certificate | Quarterly | Ensure certificate is valid |
| Security audit | Annually | Full code review |

---

## Contact & Support

For security issues or questions:
- Check existing issues: https://github.com/ebizindia/php-link-validator/issues
- Create a new issue: https://github.com/ebizindia/php-link-validator/issues/new
- For security vulnerabilities: Use GitHub Security Advisories

---

## Additional Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PHP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html
- Mozilla Observatory: https://observatory.mozilla.org/
- Security Headers: https://securityheaders.com/

---

*Last updated: 2025-10-22*
