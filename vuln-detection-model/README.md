# ML-Powered Vulnerability Detection Model

A machine learning-powered vulnerability detection system that integrates with Burp Suite Pro for enhanced security testing. The system combines deep learning models with pattern matching to identify potential security vulnerabilities in source code.

## Features

- ML-powered vulnerability detection using CodeBERT
- Pattern-based vulnerability scanning
- Proof of Concept (PoC) generation
- Burp Suite Pro integration
- RESTful API with authentication and rate limiting
- Batch processing support
- Detailed vulnerability reporting

## Components

### 1. ML Model
- Based on Microsoft's CodeBERT
- Fine-tuned for vulnerability detection
- Supports multiple vulnerability types:
  - Command Injection
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Server-Side Request Forgery (SSRF)
  - Deserialization
  - File Inclusion

### 2. API Server
- FastAPI-based RESTful API
- Endpoints:
  - `/detect`: Single vulnerability detection
  - `/batch-detect`: Batch vulnerability detection
  - `/poc`: PoC generation
  - `/health`: API health check
- Security features:
  - API key authentication
  - Rate limiting
  - Request logging
  - CORS support

### 3. Burp Suite Extension
- Java-based Burp Suite Pro extension
- Features:
  - Configurable API settings
  - Real-time vulnerability scanning
  - Custom UI panel
  - Detailed scan results
  - PoC generation integration

## Installation

### Prerequisites
- Python 3.8+
- Java 21+ (for Burp Suite extension)
- Burp Suite Pro
- PyTorch
- CUDA-capable GPU (recommended for better performance)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vuln-detection-model.git
cd vuln-detection-model
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Build the Burp Suite extension:
```bash
cd java
javac -cp "burpsuite_pro.jar" burp/*.java
jar cf vulndetector.jar burp/*.class
```

## Usage

### Starting the API Server

1. Set environment variables:
```bash
export API_KEY=your_secure_api_key
export MODEL_PATH=path_to_model
```

2. Start the server:
```bash
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```

### Installing the Burp Suite Extension

1. In Burp Suite Pro, go to Extender > Extensions
2. Click "Add"
3. Select the generated `vulndetector.jar` file
4. Configure the extension with your API URL and key

### Using the Extension

1. Configure API settings in the "ML Vuln Detector" tab
2. Test the connection to ensure proper setup
3. Start scanning to analyze requests/responses
4. View results in the Scanner tab
5. Generate PoCs for detected vulnerabilities

## API Documentation

### Endpoints

#### POST /detect
Detect vulnerabilities in a single code snippet.

Request:
```json
{
    "code": "string",
    "confidence_threshold": 0.7
}
```

Response:
```json
{
    "vulnerable": true,
    "ml_confidence": 0.95,
    "findings": [
        {
            "type": "sql_injection",
            "description": "SQL injection vulnerability detected",
            "severity": "high",
            "line": 10,
            "match": "query = 'SELECT * FROM users WHERE id = ' + user_input",
            "context": "..."
        }
    ],
    "summary": {
        "total_findings": 1,
        "severity_counts": {"high": 1, "medium": 0, "low": 0},
        "vulnerability_types": ["sql_injection"]
    }
}
```

#### POST /poc
Generate a proof of concept for a detected vulnerability.

Request:
```json
{
    "code": "string",
    "vulnerability_type": "sql_injection"
}
```

Response:
```json
{
    "success": true,
    "vulnerability_type": "sql_injection",
    "poc": "# SQL Injection PoC\npayload = \"' OR '1'='1\"...",
    "mitigations": [
        "Use parameterized queries",
        "Implement input validation"
    ]
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Microsoft for the CodeBERT model
- PortSwigger for Burp Suite Pro
- The FastAPI team
- Contributors and maintainers

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
