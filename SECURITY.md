# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Yes             |
| 1.0.x   | ⚠️ Limited support |
| < 1.0   | ❌ No              |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 🔒 Private Disclosure

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues privately by:

1. **Email**: Send details to `ebizindia@gmail.com`
2. **Subject**: Use "SECURITY: Broken Link Checker - [Brief Description]"
3. **Include**:
   - Detailed description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if available)

### 📋 What to Include

When reporting a vulnerability, please provide:

- **Vulnerability Type**: (e.g., XSS, SQL Injection, CSRF, etc.)
- **Affected Component**: Which part of the code is affected
- **Attack Vector**: How the vulnerability can be exploited
- **Impact**: What an attacker could achieve
- **Proof of Concept**: Steps or code to demonstrate the issue
- **Environment**: PHP version, server configuration, etc.

### ⏱️ Response Timeline

We aim to respond to security reports within:

- **Initial Response**: 48 hours
- **Vulnerability Assessment**: 5 business days
- **Fix Development**: 10 business days (depending on complexity)
- **Public Disclosure**: 30 days after fix release

### 🛡️ Security Measures

Our application implements several security measures:

#### Input Validation
- URL sanitization using `filter_var()`
- Domain validation and normalization
- Protection against malicious URLs

#### Output Security
- HTML entity encoding with `htmlspecialchars()`
- Proper email header sanitization
- XSS prevention in dynamic content

#### Network Security
- SSL certificate verification (configurable)
- Timeout limits to prevent DoS
- Rate limiting through batch processing
- Domain blacklisting for known malicious sites

#### Server Security
- No file system write operations
- No database connections (stateless)
- Memory limit enforcement
- Execution time limits

### 🚨 Known Security Considerations

#### Potential Risks
1. **Server-Side Request Forgery (SSRF)**
   - The tool makes HTTP requests to user-provided URLs
   - Mitigation: URL validation and domain restrictions

2. **Denial of Service (DoS)**
   - Large crawls could consume server resources
   - Mitigation: Execution time limits, memory limits, page limits

3. **Information Disclosure**
   - Error messages might reveal server information
   - Mitigation: Generic error messages in production

#### Recommended Security Configuration

```php
// Recommended PHP settings
ini_set('max_execution_time', 300);     // Limit execution time
ini_set('memory_limit', '256M');        // Limit memory usage
ini_set('display_errors', 0);           // Hide errors in production
ini_set('log_errors', 1);               // Log errors instead

// Additional security headers (add to your web server config)
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
```

### 🔧 Secure Deployment

#### Web Server Configuration
```apache
# Apache .htaccess example
<Files "*.log">
    Order allow,deny
    Deny from all
</Files>

# Prevent access to sensitive files
<FilesMatch "\.(bak|backup|old|tmp)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

#### PHP Configuration
```ini
; Recommended php.ini settings
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
display_errors = Off
log_errors = On
```

### 🏆 Security Hall of Fame

We appreciate security researchers who help improve our project:

- *No reports yet - be the first!*

### 📚 Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PHP Security Guide](https://www.php.net/manual/en/security.php)
- [Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

### 🔄 Security Updates

Security updates will be:
- Released as patch versions (e.g., 2.0.1)
- Documented in the changelog
- Announced via GitHub releases
- Communicated to users who reported the issue

### ⚖️ Responsible Disclosure

We follow responsible disclosure practices:
1. Security issues are fixed before public disclosure
2. Credit is given to researchers (with permission)
3. Details are shared after fixes are widely deployed
4. We coordinate with affected users when possible

---

Thank you for helping keep the Broken Link Checker secure! 🛡️