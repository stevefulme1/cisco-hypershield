# Contributing to stevefulme1.hypershield

Thank you for your interest in contributing to the Cisco Hypershield Ansible
collection. This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch from `main`
4. Make your changes
5. Submit a pull request

## Development Environment

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install ansible-lint yamllint pytest pytest-ansible

# Install the collection in development mode
mkdir -p ~/.ansible/collections/ansible_collections/stevefulme1
ln -s "$(pwd)" ~/.ansible/collections/ansible_collections/stevefulme1/hypershield
```

## Code Standards

### Modules

- Every module must include `DOCUMENTATION`, `EXAMPLES`, and `RETURN` docstrings
- Module `argument_spec` must match `DOCUMENTATION` options exactly
- Include GPL-3.0-or-later license header
- Use `AnsibleModule` from `ansible.module_utils.basic`
- Support check mode where applicable
- Use `no_log=True` for sensitive parameters

### Roles

- Include `meta/main.yml` with role metadata
- Include `README.md` with usage examples
- Use `defaults/main.yml` for all configurable variables
- Prefix all role variables with the role name

### Tests

- Unit tests go in `tests/unit/plugins/modules/`
- Integration tests go in `tests/integration/targets/`
- All new modules require corresponding unit tests

## Linting

Run linters before submitting:

```bash
ansible-lint
yamllint .
```

## Commit Messages

Use conventional commit format:

```
type(scope): description

feat(modules): add hypershield_policy module
fix(module_utils): handle API timeout correctly
docs(README): update installation instructions
test(unit): add tests for hypershield_dpu module
```

## Pull Request Process

1. Update documentation for any changed functionality
2. Add or update tests as needed
3. Ensure all linters pass
4. Update CHANGELOG.md with your changes
5. Request review from a maintainer

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include Ansible version, Python version, and collection version
- Provide minimal reproducible examples when possible

## License

By contributing, you agree that your contributions will be licensed under the
GPL-3.0-or-later license.
