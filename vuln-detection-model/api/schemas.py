from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class DetectionRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze")
    confidence_threshold: Optional[float] = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for ML detection"
    )

class Finding(BaseModel):
    type: str
    description: str
    severity: str
    line: int
    match: str
    context: str

class Summary(BaseModel):
    total_findings: int
    severity_counts: Dict[str, int]
    vulnerability_types: List[str]

class DetectionResponse(BaseModel):
    vulnerable: bool
    ml_confidence: float
    findings: List[Finding]
    summary: Summary
    details: Optional[str]

class PoCRequest(BaseModel):
    code: str
    vulnerability_type: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class PoCResponse(BaseModel):
    success: bool
    vulnerability_type: Optional[str]
    poc: Optional[str]
    mitigations: Optional[List[str]]
    message: Optional[str]

class BatchDetectionRequest(BaseModel):
    items: List[DetectionRequest] = Field(..., max_items=50)

class BatchDetectionResponse(BaseModel):
    results: List[DetectionResponse]
    summary: Dict[str, Any]

class HealthCheckResponse(BaseModel):
    status: str
    version: str
    model_info: Dict[str, Any]
