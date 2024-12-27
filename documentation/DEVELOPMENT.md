# Development Guide

## Getting Started

### Environment Setup

1. **Prerequisites**:
   - Python 3.9+
   - Git
   - VS Code (recommended)

2. **Clone and Setup**:
   ```bash
   git clone https://github.com/reconsumeralization/BugBounty.git
   cd BugBounty
   ```

3. **Virtual Environment**:
   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   # Linux/MacOS
   source venv/bin/activate
   ```

4. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Setup Pre-commit Hooks**:
   ```bash
   # Windows
   .\scripts\setup_hooks.ps1
   # Linux/MacOS
   ./scripts/setup_hooks.sh
   ```

### Development Environment

1. **VS Code Extensions**:
   - Python
   - Pylance
   - Black Formatter
   - isort
   - GitLens
   - Python Test Explorer

2. **Workspace Settings**:
   The repository includes `.vscode/settings.json` with recommended settings.

## Code Style

### Python Standards

1. **Type Hints**:
   ```python
   from typing import List, Dict, Optional

   def process_findings(
       findings: List[Dict[str, Any]],
       threshold: Optional[float] = None
   ) -> List[Dict[str, Any]]:
       # Implementation
       pass
   ```

2. **Docstrings**:
   ```python
   def analyze_vulnerability(vuln_type: str) -> AnalysisResult:
       """Analyze a specific type of vulnerability.

       Args:
           vuln_type: Type of vulnerability to analyze

       Returns:
           AnalysisResult containing analysis details

       Raises:
           ValueError: If vuln_type is not supported
       """
       pass
   ```

3. **Error Handling**:
   ```python
   try:
       result = await analyzer.analyze(target)
   except RateLimitError as e:
       logging.warning(f"Rate limit hit: {e}")
       await asyncio.sleep(e.retry_after)
   except AnalysisError as e:
       logging.error(f"Analysis failed: {e}")
       raise
   ```

### Project Structure

1. **Module Organization**:
   ```
   tools/
   ├── analysis/
   │   ├── __init__.py
   │   ├── o1_analyzer.py
   │   ├── scope_manager.py
   │   └── bug_bounty_analyzer.py
   ├── utils/
   │   ├── __init__.py
   │   ├── rate_limiter.py
   │   └── cache.py
   └── workflows/
       ├── __init__.py
       └── manual_test.py
   ```

2. **Test Organization**:
   ```
   tests/
   ├── conftest.py
   ├── test_o1_analyzer.py
   ├── test_scope_manager.py
   └── test_bug_bounty_analyzer.py
   ```

## Testing

### Writing Tests

1. **Test Structure**:
   ```python
   import pytest
   from unittest.mock import AsyncMock

   @pytest.mark.asyncio
   async def test_vulnerability_analysis():
       # Arrange
       analyzer = O1Analyzer()
       mock_llm = AsyncMock()
       analyzer.llm_client = mock_llm

       # Act
       result = await analyzer.analyze_vulnerability("sqli")

       # Assert
       assert result.severity == "high"
       assert result.confidence >= 0.8
   ```

2. **Fixtures**:
   ```python
   @pytest.fixture
   def sample_vulnerability():
       return {
           "type": "sqli",
           "severity": "high",
           "confidence": 0.9,
           "description": "SQL injection in login endpoint"
       }
   ```

3. **Running Tests**:
   ```bash
   # Run all tests
   pytest

   # Run specific test file
   pytest tests/test_o1_analyzer.py

   # Run with coverage
   pytest --cov=tools tests/
   ```

## Security Best Practices

1. **Input Validation**:
   ```python
   def validate_target(target: str) -> bool:
       if not isinstance(target, str):
           raise ValueError("Target must be a string")

       if not target.strip():
           raise ValueError("Target cannot be empty")

       if len(target) > MAX_TARGET_LENGTH:
           raise ValueError("Target exceeds maximum length")

       return True
   ```

2. **Rate Limiting**:
   ```python
   @rate_limit(max_requests=100, period=60)
   async def analyze_endpoint(endpoint: str) -> AnalysisResult:
       # Implementation
       pass
   ```

3. **Secure Configuration**:
   ```python
   def load_config(path: str) -> Dict[str, Any]:
       if not os.path.exists(path):
           raise FileNotFoundError(f"Config file not found: {path}")

       if not os.access(path, os.R_OK):
           raise PermissionError(f"Cannot read config file: {path}")

       return yaml.safe_load(open(path))
   ```

## Contributing

1. **Feature Branches**:
   ```bash
   git checkout -b feature/new-analyzer
   ```

2. **Commit Messages**:
   ```
   feat: Add new vulnerability analyzer

   - Implements advanced SQL injection detection
   - Adds unit tests for new analyzer
   - Updates documentation
   ```

3. **Pull Requests**:
   - Create PR against `main` branch
   - Ensure all tests pass
   - Update documentation
   - Add test cases
   - Request review

## Deployment

1. **Version Bumping**:
   ```bash
   # Update version in pyproject.toml
   [tool.poetry]
   version = "1.2.0"
   ```

2. **Release Process**:
   ```bash
   # Tag release
   git tag -a v1.2.0 -m "Release version 1.2.0"
   git push origin v1.2.0
   ```

## Troubleshooting

1. **Common Issues**:
   - Rate limiting errors
   - API authentication failures
   - Type checking errors
   - Pre-commit hook failures

2. **Debug Logging**:
   ```python
   import logging

   logging.basicConfig(level=logging.DEBUG)
   logger = logging.getLogger(__name__)

   logger.debug("Analysis parameters: %s", params)
   logger.info("Starting analysis for: %s", target)
   logger.warning("Rate limit approaching: %d/%d", current, limit)
   logger.error("Analysis failed: %s", error)
   ```

3. **Performance Profiling**:
   ```python
   import cProfile
   import pstats

   def profile_analysis():
       profiler = cProfile.Profile()
       profiler.enable()

       # Run analysis
       analyzer.analyze_target(target)

       profiler.disable()
       stats = pstats.Stats(profiler).sort_stats('cumtime')
       stats.print_stats()
   ```
