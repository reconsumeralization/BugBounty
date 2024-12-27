# Security Reconnaissance Automation Framework

A comprehensive framework for automating security testing and vulnerability analysis using LLM capabilities, designed to support multiple bug bounty programs.

## Project Structure

```
recon_automation/
├── config/                    # Configuration files
│   ├── programs/             # Program-specific configurations
│   │   ├── microsoft/        # Microsoft bug bounty config
│   │   ├── google/           # Google VRP config
│   │   └── infomaniak/       # Infomaniak config
│   ├── scope.yaml            # Global scope settings
│   └── recon.yaml            # Global recon settings
├── tools/                    # Core analysis tools
│   ├── analysis/            # Analysis modules
│   │   ├── o1_analyzer.py   # O1 model integration
│   │   ├── scope_manager.py # Scope validation
│   │   └── web_analyzer.py  # Web vulnerability analysis
│   ├── llm/                 # LLM integration tools
│   └── utils/               # Utility functions
├── programs/                # Program-specific code
│   ├── microsoft/           # Microsoft bug bounty
│   │   ├── analyzers/       # Custom analyzers
│   │   ├── rules/          # Program-specific rules
│   │   └── templates/      # Report templates
│   ├── google/             # Google VRP
│   └── infomaniak/         # Infomaniak program
├── tests/                   # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── programs/           # Program-specific tests
├── documentation/          # Project documentation
│   ├── programs/          # Program documentation
│   ├── API.md             # API reference
│   └── DEVELOPMENT.md     # Development guide
├── reports/               # Analysis reports
│   ├── microsoft/        # Microsoft findings
│   ├── google/          # Google VRP findings
│   └── infomaniak/      # Infomaniak findings
└── scripts/              # Utility scripts
```

## Features

- **Multi-Program Support**
  - Program-specific configurations
  - Custom analysis rules per program
  - Tailored report templates
  - Scope management per program

- **Advanced Analysis**
  - Automated security analysis using OpenAI's O1 model
  - Vulnerability chain detection and analysis
  - Scope-aware vulnerability detection
  - Comprehensive logging and monitoring

- **Security Features**
  - Rate limiting and request throttling
  - Input validation and sanitization
  - Secure configuration management
  - Audit logging and monitoring

- **Developer Tools**
  - Type-safe implementation
  - Comprehensive test suite
  - Code quality tools
  - CI/CD integration

## Quick Start

1. **Clone and Setup**:
   ```bash
   git clone https://github.com/reconsumeralization/BugBounty.git
   cd BugBounty
   ```

2. **Install Dependencies**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or .\venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

3. **Configure Program**:
   ```bash
   cp config/programs/example.yaml config/programs/your_program.yaml
   # Edit your_program.yaml with specific settings
   ```

4. **Run Analysis**:
   ```bash
   python tools/run_analysis.py --program microsoft --target example.com
   ```

## Program-Specific Guidelines

### Microsoft Bug Bounty
- Supported programs:
  - Microsoft Online Services
  - Microsoft Identity
  - Azure
  - Windows Security
- Reward ranges: $500 - $250,000
- Special focus areas:
  - Remote Code Execution
  - Elevation of Privilege
  - Security Feature Bypass

### Google VRP
- Supported platforms:
  - Google Cloud Platform
  - Android
  - Chrome
- Reward ranges: $100 - $31,337
- Special requirements:
  - Functional exploits
  - Clear security impact

### Infomaniak
- Target scope:
  - Web applications
  - API endpoints
  - Infrastructure
- Reward ranges: €100 - €10,000
- Focus areas:
  - Authentication bypass
  - Data exposure
  - Infrastructure security

## Development

See [Development Guide](documentation/DEVELOPMENT.md) for detailed setup and contribution guidelines.

## Testing

Run tests for specific programs:
```bash
pytest tests/programs/microsoft/
pytest tests/programs/google/
pytest tests/programs/infomaniak/
```

## Security

- All API keys and secrets should be stored in `.env`
- Follow program-specific security guidelines
- Respect rate limits and scope boundaries
- Report findings responsibly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
