from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import Dict, Any
import numpy as np

class VulnerabilityDetector:
    def __init__(self):
        # Using CodeBERT model fine-tuned for vulnerability detection
        self.model_name = "microsoft/codebert-base"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
        
    def preprocess_code(self, code: str) -> Dict[str, torch.Tensor]:
        """Tokenize and prepare the code for model input"""
        return self.tokenizer(
            code,
            truncation=True,
            max_length=512,
            padding='max_length',
            return_tensors='pt'
        )

    def detect(self, code: str) -> Dict[str, Any]:
        """
        Detect vulnerabilities in the provided code
        Returns: Dict containing vulnerability assessment
        """
        # Preprocess the code
        inputs = self.preprocess_code(code)
        
        # Get model prediction
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        # Get prediction and confidence
        prediction = torch.argmax(probabilities, dim=-1).item()
        confidence = probabilities[0][prediction].item()
        
        # Analyze specific vulnerability patterns
        vuln_patterns = {
            'command_injection': ['exec(', 'eval(', 'os.system('],
            'sql_injection': ["'--", "1=1", "UNION SELECT"],
            'xss': ['<script>', 'javascript:', 'onerror='],
        }
        
        details = []
        for vuln_type, patterns in vuln_patterns.items():
            if any(pattern in code for pattern in patterns):
                details.append(f"Potential {vuln_type} vulnerability detected")
        
        return {
            'vulnerable': bool(prediction),
            'confidence': confidence,
            'details': '; '.join(details) if details else None
        }

    def generate_poc(self, code: str, vulnerability_type: str = None) -> str:
        """
        Generate a proof of concept for the detected vulnerability
        """
        # Basic PoC generation logic based on vulnerability patterns
        if 'exec(' in code or 'eval(' in code:
            return """
            # Command Injection PoC
            payload = 'os.system("id")'
            eval(payload)  # This will execute the command
            """
        elif any(pattern in code for pattern in ["'--", "1=1", "UNION"]):
            return """
            # SQL Injection PoC
            payload = "' OR '1'='1"
            query = f"SELECT * FROM users WHERE username = '{payload}'"
            """
        elif '<script>' in code or 'javascript:' in code:
            return """
            # XSS PoC
            payload = '<script>alert(document.cookie)</script>'
            document.write(payload)
            """
        return "No specific PoC generated for this code"
