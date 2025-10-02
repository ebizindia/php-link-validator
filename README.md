# PHP Link Validator

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP Version](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg)
![GitHub Issues](https://img.shields.io/github/issues/ebizindia/php-link-validator)
![GitHub Stars](https://img.shields.io/github/stars/ebizindia/php-link-validator)

A powerful, optimized PHP-based broken link checker that crawls websites to identify broken internal and external links. Features multi-cURL processing, memory optimization, and comprehensive reporting.

## ✨ Features

- **Multi-cURL Processing**: Checks multiple links simultaneously for faster performance
- **Memory Optimized**: Efficient memory management for large websites
- **Internal & External Link Checking**: Comprehensive link validation
- **Real-time Progress**: Live status updates during crawling
- **Email Reports**: Automated email notifications with detailed reports
- **Performance Metrics**: Execution time and memory usage tracking
- **Responsive Design**: Bootstrap-powered responsive interface
- **Batch Processing**: Handles large websites efficiently

## 📋 Requirements

- PHP 7.4 or higher (PHP 8.x supported)
- cURL extension enabled
- DOMDocument extension
- Web server (Apache/Nginx)
- At least 512MB PHP memory limit (recommended)

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/ebizindia/php-link-validator.git
cd php-link-validator
```

### 2. Configure PHP settings (optional but recommended)

```php
ini_set('max_execution_time', 600);
ini_set('memory_limit', '512M');
```

### 3. Upload to your web server

- Upload all files to your web server directory
- Ensure PHP has write permissions if needed

### 4. Access the tool

- Navigate to `http://yourdomain.com/path-to-tool/index.php`

## 📖 Usage

1. **Enter Website URL**: Input the domain you want to check
2. **Configure Options**:
   - Set maximum pages to crawl (1-1000)
   - Choose to check external links or internal only
   - Enable email notifications
3. **Start Crawling**: Click "Check Links" to begin analysis
4. **View Results**: Review broken links with detailed error information

## ⚙️ Configuration

All settings can be easily modified at the top of `index.php` in the configuration section:

### Performance Settings

```php
// === PERFORMANCE SETTINGS ===
define('MAX_EXECUTION_TIME', 600);      // Maximum script execution time (seconds)
define('MEMORY_LIMIT', '512M');         // PHP memory limit
define('MAX_PAGES_DEFAULT', 100);       // Default maximum pages to crawl
define('PAGE_TIMEOUT', 8);              // Timeout for fetching pages (seconds)
define('LINK_TIMEOUT', 3);              // Timeout for checking individual links (seconds)
```

### Multi-cURL Optimization

```php
// === MULTI-CURL OPTIMIZATION ===
define('MAX_CONCURRENT_REQUESTS', 10);  // Number of simultaneous link checks
define('BATCH_SIZE', 20);               // Links processed per batch
define('MAX_LINKS_PER_PAGE', 30);       // Maximum links to check per page
```

### Email Configuration

```php
// === EMAIL SETTINGS ===
define('EMAIL_FROM', 'noreply@example.com');    // From email address
define('EMAIL_TO', 'admin@example.com');        // Default recipient email
```

**Note**: Update the email addresses with your actual email addresses.

Update the email settings in the code:

```php
$headers = "From: noreply@example.com\r\n";
// Change recipient email
mail('admin@example.com', $subject, $emailBody, $headers);
```

## 🚄 Performance Optimization

- **Concurrent Processing**: Up to 10 simultaneous link checks
- **Smart Caching**: Avoids duplicate link checks
- **Memory Management**: Automatic garbage collection
- **Batch Processing**: Handles large sites efficiently
- **Domain Filtering**: Skips known slow domains
- **Request Optimization**: Uses HEAD requests for external links

### Skip Slow Domains

Add domains to skip during external link checking:

```php
private $skipExternalDomains = [
    'facebook.com',
    'twitter.com',
    'youtube.com'
];
```

### Adjust Timeouts

Modify timeouts based on your needs:

```php
private $timeout = 8;           // Page crawling timeout
private $linkTimeout = 3;       // Link validation timeout
```

## 📊 Reports

The tool provides detailed reports including:

- Source page URL
- Broken link URL
- Link text/anchor text
- Error type and message
- Link category (internal/external)
- Link type (anchor/image)

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Credits

Developed by [Ebizindia](https://www.ebizindia.com) - Your partner in web development and digital solutions.

## 🐛 Support & Issues

If you encounter any issues or need support:

- Check existing [Issues](https://github.com/ebizindia/php-link-validator/issues)
- Create a new issue with detailed information
- Include PHP version, server configuration, and error messages

## 📝 Changelog

### Version 2.0.0 (Latest)
- Added multi-cURL processing
- Implemented memory optimization
- Enhanced performance metrics
- Improved error handling
- Added batch processing

### Version 1.0.0
- Initial release
- Basic link checking functionality
- Email reporting
- Bootstrap interface

## 💡 Performance Tips

1. **Increase PHP Limits**: Set higher memory and execution time limits
2. **Optimize Batch Size**: Adjust based on server capabilities
3. **Use HEAD Requests**: Enabled by default for external links
4. **Monitor Memory**: Built-in memory tracking helps identify issues
5. **Limit Crawl Depth**: Set appropriate page limits for large sites

## 🌟 Show Your Support

If you find this project helpful, please consider giving it a ⭐️ on GitHub!

---

Made with ❤️ by [Ebizindia Team](https://www.ebizindia.com)
