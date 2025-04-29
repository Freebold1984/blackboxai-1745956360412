from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import Dict, Any, List, Optional
import numpy as np
from .patterns import VulnerabilityPatterns
from .poc_generator import PoCGenerator

class VulnerabilityDetector:
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """
        Initialize the vulnerability detector with a pre-trained model
        Args:
            model_name: Name of the pre-trained model to use
        """
        self.model_name = model_name
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
        self.patterns = VulnerabilityPatterns()
        self.poc_generator = PoCGenerator()
        
    def preprocess_code(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Tokenize and prepare the code for model input
        Args:
            code: Source code to analyze
        Returns:
            Tokenized input ready for model
        """
        return self.tokenizer(
            code,
            truncation=True,
            max_length=512,
            padding='max_length',
            return_tensors='pt'
        )

    def get_model_prediction(self, inputs: Dict[str, torch.Tensor]) -> Dict[str, float]:
        """
        Get model prediction for preprocessed input
        Args:
            inputs: Preprocessed input tensors
        Returns:
            Dictionary containing prediction and confidence
        """
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        prediction = torch.argmax(probabilities, dim=-1).item()
        confidence = probabilities[0][prediction].item()
        
        return {
            'is_vulnerable': bool(prediction),
            'confidence': confidence
        }

    def analyze_patterns(self, code: str) -> List[Dict]:
        """
        Analyze code for known vulnerability patterns
        Args:
            code: Source code to analyze
        Returns:
            List of detected vulnerabilities with details
        """
        return self.patterns.check_patterns(code)

    def detect(self, code: str, confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """
        Comprehensive vulnerability detection
        Args:
            code: Source code to analyze
            confidence_threshold: Minimum confidence threshold for ML detection
        Returns:
            Detailed vulnerability assessment
        """
        # Get ML model prediction
        inputs = self.preprocess_code(code)
        ml_result = self.get_model_prediction(inputs)
        
        # Get pattern-based findings
        pattern_findings = self.analyze_patterns(code)
        
        # Determine overall vulnerability status
        is_vulnerable = (
            ml_result['is_vulnerable'] and ml_result['confidence'] >= confidence_threshold
        ) or len(pattern_findings) > 0
        
        # Generate response
        result = {
            'vulnerable': is_vulnerable,
            'ml_confidence': ml_result['confidence'],
            'findings': pattern_findings,
            'summary': {
                'total_findings': len(pattern_findings),
                'severity_counts': self._count_severities(pattern_findings),
                'vulnerability_types': self._get_unique_types(pattern_findings)
            }
        }
        
        # Add details if vulnerabilities found
        if is_vulnerable:
            result['details'] = self._generate_details(pattern_findings)
        
        return result

    def generate_poc(self, code: str, vulnerability_type: Optional[str] = None, 
                    context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate proof of concept for detected vulnerabilities
        Args:
            code: Source code to analyze
            vulnerability_type: Specific vulnerability type to generate PoC for
            context: Additional context for PoC generation
        Returns:
            Dictionary containing PoC and related information
        """
        # First detect vulnerabilities if type not specified
        if not vulnerability_type:
            detection_result = self.detect(code)
            if not detection_result['vulnerable']:
                return {
                    'success': False,
                    'message': 'No vulnerabilities detected'
                }
            
            # Use the first detected vulnerability type
            if detection_result['findings']:
                vulnerability_type = detection_result['findings'][0]['type']
                context = detection_result['findings'][0]
        
        # Generate PoC
        if not context:
            context = {}
            
        poc = self.poc_generator.generate_poc(
            vulnerability_type=vulnerability_type,
            context=context,
            advanced=True
        )
        
        if not poc:
            return {
                'success': False,
                'message': f'Could not generate PoC for vulnerability type: {vulnerability_type}'
            }
        
        return {
            'success': True,
            'vulnerability_type': vulnerability_type,
            'poc': poc,
            'mitigations': self.poc_generator.get_mitigation_steps(vulnerability_type)
        }

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity level"""
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _get_unique_types(self, findings: List[Dict]) -> List[str]:
        """Get unique vulnerability types from findings"""
        return list(set(finding['type'] for finding in findings))

    def _generate_details(self, findings: List[Dict]) -> str:
        """Generate detailed description of findings"""
        if not findings:
            return "No specific vulnerability details available"
        
        details = []
        for finding in findings:
            details.append(
                f"- {finding['type'].upper()}: {finding['description']}\n"
                f"  Severity: {finding['severity']}\n"
                f"  Line: {finding['line']}\n"
                f"  Context: {finding['context']}"
            )
        
        return "\n\n".join(details)
