# Contributing to configsafe

Thanks for your interest in contributing!

## Quick Start

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/configsafe`
3. Install: `pip install -e .`
4. Make changes
5. Test: Run `configsafe` on sample config files
6. Push and open a PR

## What to Contribute

- Support for additional config formats (TOML, YAML, HCL, etc.)
- New security rules and patterns
- Improved secret detection
- False positive reduction
- Integration with secret scanning tools
- Custom rule definitions (rule engine)

## Code Style

- Python 3.7+ compatible
- Keep dependencies minimal
- Clear variable names
- Well-documented security patterns

## Testing

Test with various config formats:
- .env files
- INI/conf files
- JSON configs
- XML configs
- Application-specific formats (nginx.conf, etc.)

**Security Testing:**
- Test with known vulnerable configurations
- Verify no false negatives on real secrets
- Check false positive rate on common patterns

## Reporting Issues

Open an issue with:
- Config file format you're testing
- Sample config (with secrets redacted)
- Expected vs. actual findings

**Security:** If you discover a bypass or false negative that could expose secrets, please email the maintainer directly.

## Ideas for Contributions

- Integration with CI/CD tools
- Pre-commit hook support
- IDE/editor plugins
- Automatic remediation suggestions
- Config file sanitization (remove secrets)
- Policy-as-code (define required/forbidden patterns)
- Comparison with known-good baseline
- Terraform/CloudFormation support

## License

By contributing, you agree your contributions will be licensed under MIT.
