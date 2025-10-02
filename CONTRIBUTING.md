# Contributing to Broken Link Checker

Thank you for your interest in contributing to the Broken Link Checker tool! We welcome contributions from the community.

## 🤝 How to Contribute

### Reporting Issues
1. Check existing issues first to avoid duplicates
2. Use the issue template when creating new issues
3. Include detailed information:
   - PHP version
   - Server configuration
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs

### Submitting Changes
1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test your changes thoroughly
4. **Commit your changes**
   ```bash
   git commit -m "Add: brief description of changes"
   ```
5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
6. **Create a Pull Request**

## 📝 Code Style Guidelines

### PHP Standards
- Follow PSR-12 coding standards
- Use meaningful variable and function names
- Add PHPDoc comments for functions and classes
- Keep functions focused and single-purpose

### Example:
```php
/**
 * Checks if a URL belongs to the same domain
 * 
 * @param string $url The URL to check
 * @return bool True if same domain, false otherwise
 */
private function isSameDomain($url) {
    // Implementation here
}
```

### HTML/CSS
- Use semantic HTML elements
- Follow Bootstrap conventions
- Keep CSS organized and commented
- Ensure responsive design

## 🧪 Testing

Before submitting:
1. Test with different website types
2. Verify memory usage with large sites
3. Check error handling with invalid URLs
4. Test email functionality
5. Validate HTML output

## 🔧 Development Setup

1. **Local Environment**
   ```bash
   # Clone your fork
   git clone https://github.com/yourusername/broken-link-checker.git
   cd broken-link-checker
   
   # Set up local web server (XAMPP, WAMP, or similar)
   # Ensure PHP 7.4+ with cURL extension
   ```

2. **Configuration**
   - Set appropriate PHP limits for testing
   - Configure email settings for testing
   - Use test domains for development

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows project style guidelines
- [ ] Changes are tested thoroughly
- [ ] Documentation is updated if needed
- [ ] Commit messages are clear and descriptive
- [ ] No merge conflicts exist

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Code refactoring

## Testing
- [ ] Tested with small websites (< 50 pages)
- [ ] Tested with large websites (> 100 pages)
- [ ] Tested error handling
- [ ] Verified memory usage
- [ ] Tested email functionality

## Screenshots (if applicable)
Add screenshots for UI changes
```

## 🎯 Areas for Contribution

### High Priority
- Performance optimizations
- Better error handling
- Additional link types support
- Improved memory management
- Enhanced reporting features

### Medium Priority
- UI/UX improvements
- Additional export formats
- Configuration options
- Logging enhancements
- Code documentation

### Low Priority
- Code refactoring
- Additional tests
- Accessibility improvements
- Internationalization

## 🚀 Feature Requests

When suggesting new features:
1. Check existing issues and discussions
2. Provide clear use case and benefits
3. Consider implementation complexity
4. Think about backward compatibility

## 📞 Getting Help

- Create an issue for questions
- Check existing documentation
- Review code comments for understanding
- Contact maintainers for major changes

## 🏆 Recognition

Contributors will be:
- Listed in the README
- Mentioned in release notes
- Credited in code comments (for significant contributions)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make this tool better! 🙏