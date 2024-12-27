# Security Reconnaissance Automation Framework

A comprehensive framework for automating security testing and vulnerability analysis using LLM capabilities.

## Features

- Automated security analysis using LLM
- Scope-aware vulnerability detection
- Caching and rate limiting
- Comprehensive logging and monitoring
- Integration with security tools
- Type-safe implementation

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Project Structure

```
.
├── config/
│   └── scope/          # Scope definitions
├── core/               # Core functionality
├── modules/            # Feature modules
├── analysis/           # Analysis tools
├── tests/              # Test suite
└── tools/
    ├── manual_testing/ # Manual testing helpers
    └── analysis/       # Analysis tools
```

## Development

### Prerequisites

- Python 3.9+
- Git
- Virtual environment

### Code Style

- Follow PEP 8
- Use type hints
- Write comprehensive docstrings
- Include unit tests

### Testing

Run tests:
```bash
pytest tests/ -v
```

Run linting:
```bash
pylint tools core modules analysis tests
```

Run type checking:
```bash
mypy tools core modules analysis tests
```

## Security Considerations

- Never commit sensitive data
- Follow secure coding practices
- Validate all inputs
- Handle errors securely
- Use rate limiting
- Implement proper access controls

## Contributing

1. Create a feature branch
2. Make changes
3. Run tests and linting
4. Submit pull request

## License

[Your License Here]

## Code Quality and Linting

This project uses several tools to maintain code quality and consistency:

### Automatic Formatting

- **Black**: Code formatter that enforces a consistent style
- **isort**: Sorts and formats import statements
- **Ruff**: Fast Python linter and code formatter

### Static Type Checking

- **mypy**: Static type checker for Python
- Strict type checking enabled
- Type stubs for third-party libraries

### Code Analysis

- **pylint**: Python code analysis tool
- Custom configuration in `.pylintrc`
- Enforces coding standards and catches potential errors

### Security Checks

- **Safety**: Checks Python dependencies for known security vulnerabilities
- **Pre-commit hooks**: Includes security-focused checks

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality before commits. To set up:

#### Windows
```powershell
# From the project root
.\scripts\setup_hooks.ps1
```

#### Linux/MacOS
```bash
# From the project root
./scripts/setup_hooks.sh
```

### Configuration Files

- `pyproject.toml`: Configuration for Black and mypy
- `.pylintrc`: Pylint configuration
- `.pre-commit-config.yaml`: Pre-commit hooks configuration

### Continuous Integration

The linting and type checking are part of the CI pipeline and must pass before merging:

- Black formatting check
- mypy type checking
- pylint code analysis
- Safety security check
- Unit tests with pytest

### IDE Integration

For VS Code users, add these settings to your workspace:

```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

### Manual Checks

Run individual checks:

```bash
# Format code
black .

# Sort imports
isort .

# Type checking
mypy .

# Lint code
pylint tools tests

# Security check
safety check
```
# BugBounty
