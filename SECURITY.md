# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in this collection, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to **sfulmer@redhat.com** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

You should receive a response within 48 hours acknowledging receipt. We will
work with you to understand the issue and coordinate a fix and disclosure
timeline.

## Security Best Practices

When using this collection:

- Store credentials using Ansible Vault or an external secrets manager
- Use `no_log: true` for tasks that handle sensitive data
- Restrict API token permissions to the minimum required scope
- Rotate API credentials regularly
- Review playbook output before sharing to ensure no secrets are leaked
