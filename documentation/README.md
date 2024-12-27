# Infomaniak Bug Bounty Testing Documentation

## Overview
This repository contains tools and configurations for testing Infomaniak's bug bounty program.

## Repository Structure
infomaniak-bb/
├── config/           # Configuration files
│   ├── scope.yaml   # Target scope definition
│   └── recon.yaml   # Reconnaissance config
├── documentation/    # Project documentation
├── exploits/        # Proof of Concept exploits
│   ├── subdomain/   # Subdomain takeover exploits
│   ├── network/     # Network-level exploits
│   ├── web/         # Web application exploits
│   └── api/         # API-related exploits
├── recon/           # Reconnaissance data
├── reports/         # Bug reports and templates
├── scans/          # Scan results
│   ├── subdomain/  # Subdomain enumeration results
│   ├── network/    # Port scan results
│   ├── web/        # Web vulnerability scan results
│   └── api/        # API scan results
└── tools/          # Custom tools and scripts

## Quick Start
1. Set up environment:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   source .env
   ```

2. Run initial reconnaissance:
   ```bash
   python3 tools/recon_automation.py
   ```

3. Review scan results in `scans/` directory

## Testing Workflow
1. **Reconnaissance Phase**
   - Subdomain enumeration
   - Port scanning
   - Technology detection
   - Content discovery

2. **Vulnerability Assessment**
   - Web application scanning
   - API testing
   - Network vulnerability scanning
   - Manual testing

3. **Exploitation & Verification**
   - Proof of concept development
   - Impact assessment
   - Documentation

4. **Reporting**
   - Write detailed reports
   - Create minimal PoCs
   - Submit findings

## Testing Guidelines
- Respect rate limits (10 req/s)
- Test during allowed hours (09:00-18:00 CET)
- Document all findings
- Verify findings before reporting

## Bug Report Template
### Title
[Severity] Brief Description of the Vulnerability

### Description
Detailed explanation of the vulnerability

### Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

### Impact
Explain the potential impact

### Proof of Concept
