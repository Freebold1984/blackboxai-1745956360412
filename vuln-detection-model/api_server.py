from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from model import VulnerabilityDetector

app = FastAPI(title="Vulnerability Detection API")

# Initialize the vulnerability detector
detector = VulnerabilityDetector()

class DetectionRequest(BaseModel):
    code: str

class DetectionResponse(BaseModel):
    vulnerable: bool
    confidence: float
    details: Optional[str] = None

@app.post("/detect", response_model=DetectionResponse)
async def detect_vulnerability(request: DetectionRequest):
    try:
        result = detector.detect(request.code)
        return DetectionResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/confirm", response_model=DetectionResponse)
async def confirm_vulnerability(request: DetectionRequest):
    # Run a more thorough analysis by running detection multiple times
    try:
        # Run detection twice to confirm
        result1 = detector.detect(request.code)
        result2 = detector.detect(request.code)
        
        # If both detections agree, return the result with higher confidence
        if result1['vulnerable'] == result2['vulnerable']:
            return DetectionResponse(**result1 if result1['confidence'] > result2['confidence'] else result2)
        else:
            # If detections disagree, return the one with higher confidence but mark it in details
            result = result1 if result1['confidence'] > result2['confidence'] else result2
            result['details'] = f"{result.get('details', '')} (Note: Detection results were inconsistent)"
            return DetectionResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/poc")
async def generate_poc(request: DetectionRequest):
    try:
        # First detect the vulnerability
        detection_result = detector.detect(request.code)
        
        if detection_result['vulnerable']:
            # Generate PoC if vulnerability is detected
            poc = detector.generate_poc(request.code)
            return {
                "vulnerable": True,
                "poc": poc,
                "details": detection_result.get('details')
            }
        else:
            return {
                "vulnerable": False,
                "poc": None,
                "details": "No vulnerability detected"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
