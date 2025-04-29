from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
from typing import List, Dict, Any
import asyncio
from datetime import datetime
import logging
import sys

from .schemas import (
    DetectionRequest, DetectionResponse, PoCRequest, PoCResponse,
    BatchDetectionRequest, BatchDetectionResponse, HealthCheckResponse
)
from ..model.detector import VulnerabilityDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vuln_detection.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Vulnerability Detection API",
    description="API for detecting vulnerabilities in code using ML and pattern matching",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

# Rate limiting
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS = 100  # requests per window
request_history: Dict[str, List[float]] = {}

# Initialize the vulnerability detector
detector = VulnerabilityDetector()

async def verify_api_key(api_key: str = Depends(api_key_header)) -> str:
    """Verify API key and return client ID"""
    # In production, replace with secure API key verification
    if not api_key or len(api_key) < 32:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

async def check_rate_limit(request: Request, client_id: str = Depends(verify_api_key)):
    """Check if client has exceeded rate limit"""
    now = time.time()
    
    if client_id not in request_history:
        request_history[client_id] = []
    
    # Remove old requests
    request_history[client_id] = [
        req_time for req_time in request_history[client_id]
        if now - req_time < RATE_LIMIT_WINDOW
    ]
    
    if len(request_history[client_id]) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    request_history[client_id].append(now)

@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Check API health status"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "model_info": {
            "name": detector.model_name,
            "type": "CodeBERT",
            "last_updated": datetime.now().isoformat()
        }
    }

@app.post("/detect", response_model=DetectionResponse)
async def detect_vulnerability(
    request: DetectionRequest,
    client_id: str = Depends(check_rate_limit)
):
    """
    Detect vulnerabilities in provided code
    """
    try:
        logger.info(f"Processing detection request from client: {client_id}")
        result = detector.detect(
            code=request.code,
            confidence_threshold=request.confidence_threshold
        )
        return DetectionResponse(**result)
    except Exception as e:
        logger.error(f"Error processing detection request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch-detect", response_model=BatchDetectionResponse)
async def batch_detect_vulnerabilities(
    request: BatchDetectionRequest,
    client_id: str = Depends(check_rate_limit)
):
    """
    Process multiple detection requests in batch
    """
    try:
        logger.info(f"Processing batch detection request from client: {client_id}")
        results = []
        total_vulnerabilities = 0
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        
        for item in request.items:
            result = detector.detect(
                code=item.code,
                confidence_threshold=item.confidence_threshold
            )
            results.append(DetectionResponse(**result))
            
            if result["vulnerable"]:
                total_vulnerabilities += 1
                for finding in result["findings"]:
                    severity_counts[finding["severity"]] += 1
        
        return BatchDetectionResponse(
            results=results,
            summary={
                "total_requests": len(request.items),
                "total_vulnerabilities": total_vulnerabilities,
                "severity_counts": severity_counts
            }
        )
    except Exception as e:
        logger.error(f"Error processing batch detection request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/poc", response_model=PoCResponse)
async def generate_poc(
    request: PoCRequest,
    client_id: str = Depends(check_rate_limit)
):
    """
    Generate proof of concept for detected vulnerabilities
    """
    try:
        logger.info(f"Processing PoC generation request from client: {client_id}")
        result = detector.generate_poc(
            code=request.code,
            vulnerability_type=request.vulnerability_type,
            context=request.context
        )
        return PoCResponse(**result)
    except Exception as e:
        logger.error(f"Error generating PoC: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"Status: {response.status_code} "
        f"Duration: {duration:.3f}s"
    )
    
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": str(exc)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
