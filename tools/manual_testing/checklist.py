from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class VulnType(Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    RCE = "Remote Code Execution"
    IDOR = "Insecure Direct Object Reference"
    SSRF = "Server-Side Request Forgery"
    INFO_LEAK = "Information Leakage"
    AUTH_BYPASS = "Authentication Bypass"
    PRIV_ESC = "Privilege Escalation"

@dataclass
class TestCase:
    name: str
    endpoint: str
    vuln_type: VulnType
    description: str
    test_steps: List[str]
    expected_result: str
    notes: Optional[str] = None

@dataclass
class ServiceTest:
    service_name: str
    base_url: str
    endpoints: List[str]
    test_cases: List[TestCase]
    headers: Dict[str, str] = field(default_factory=lambda: {
        'User-Agent': 'Infomaniak-YWH-Bugbounty',  # Required by program
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    })
