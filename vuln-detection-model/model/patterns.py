from typing import Dict, List, Pattern
import re

class VulnerabilityPatterns:
    def __init__(self):
        # Comprehensive vulnerability patterns with regex
        self.patterns: Dict[str, List[Dict[str, Pattern]]] = {
            'command_injection': [
                {'pattern': re.compile(r'(?:exec|eval|os\.system|subprocess\.(?:call|run|Popen)|shell\s*=\s*True)', re.I),
                 'description': 'Command execution function detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:`.*`|\$\(.*\))', re.I),
                 'description': 'Shell command substitution detected',
                 'severity': 'high'}
            ],
            'sql_injection': [
                {'pattern': re.compile(r"(?:'|\").*(?:--|;|/\*|#|OR\s+['\"]\d+['\"]=['\"]\d+)", re.I),
                 'description': 'SQL injection pattern detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:UNION\s+ALL|UNION\s+SELECT|OR\s+1\s*=\s*1)', re.I),
                 'description': 'SQL UNION/OR injection pattern detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:INTO\s+OUTFILE|LOAD_FILE)', re.I),
                 'description': 'SQL file operation detected',
                 'severity': 'high'}
            ],
            'xss': [
                {'pattern': re.compile(r'<[^>]*script.*?>|javascript:|data:', re.I),
                 'description': 'Basic XSS pattern detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:on\w+\s*=|(?:src|href)\s*=\s*[\'"]?(?:javascript|data))', re.I),
                 'description': 'Event handler/protocol XSS detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;', re.I),
                 'description': 'Encoded XSS pattern detected',
                 'severity': 'medium'}
            ],
            'path_traversal': [
                {'pattern': re.compile(r'(?:\.\./|\.\./\./|~/).*(?:etc/passwd|windows/win.ini)', re.I),
                 'description': 'Path traversal pattern detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:%2e%2e%2f|%2e%2e/|\.\.%2f|\.\./)', re.I),
                 'description': 'Encoded path traversal detected',
                 'severity': 'high'}
            ],
            'ssrf': [
                {'pattern': re.compile(r'(?:file|dict|gopher|php|glob|data|phar|http|ftp)://\S+', re.I),
                 'description': 'Potential SSRF URL detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'localhost|127\.0\.0\.1|0\.0\.0\.0|[::]', re.I),
                 'description': 'Internal IP/hostname detected',
                 'severity': 'high'}
            ],
            'deserialization': [
                {'pattern': re.compile(r'(?:pickle\.|marshal\.|yaml\.load|json\.loads)', re.I),
                 'description': 'Deserialization function detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'__reduce__|__getstate__|__setstate__', re.I),
                 'description': 'Serialization magic method detected',
                 'severity': 'medium'}
            ],
            'file_inclusion': [
                {'pattern': re.compile(r'(?:include|require|include_once|require_once)\s*[\'"]?\$.*[\'"]?', re.I),
                 'description': 'Dynamic file inclusion detected',
                 'severity': 'high'},
                {'pattern': re.compile(r'(?:file_get_contents|fopen|readfile)\s*\(.*\$', re.I),
                 'description': 'Dynamic file operation detected',
                 'severity': 'high'}
            ]
        }

    def check_patterns(self, code: str) -> List[Dict]:
        """
        Check code against all vulnerability patterns
        Returns: List of detected vulnerabilities with details
        """
        findings = []
        
        for vuln_type, patterns in self.patterns.items():
            for pattern_dict in patterns:
                matches = pattern_dict['pattern'].finditer(code)
                for match in matches:
                    findings.append({
                        'type': vuln_type,
                        'description': pattern_dict['description'],
                        'severity': pattern_dict['severity'],
                        'line': code.count('\n', 0, match.start()) + 1,
                        'match': match.group(0),
                        'context': code[max(0, match.start()-50):min(len(code), match.end()+50)]
                    })
        
        return findings

    def get_pattern_description(self, vuln_type: str) -> str:
        """Get description of vulnerability patterns for a specific type"""
        if vuln_type in self.patterns:
            return '\n'.join([p['description'] for p in self.patterns[vuln_type]])
        return "Unknown vulnerability type"
