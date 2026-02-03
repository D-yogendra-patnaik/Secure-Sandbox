import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

import requests
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .analyzer.static import run_semgrep_analysis
# from .analyzer.dynamic import run_dynamic_analysis
from .features import extract_features
from .model import load_model, predict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Malware Detection API",
    description="Secure malware detection with static analysis, ML, and sandboxed execution",
    version="1.0.0"
)

MAX_FILE_SIZE = 10 * 1024 * 1024


class URLRequest(BaseModel):
    url: str


@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "Malware Detection API",
        "version": "1.0"
    }


@app.get("/web", response_class=HTMLResponse)
async def web_interface():
    template_path = Path(__file__).parent / "templates" / "index.html"
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/analyze")
async def analyze(file: Optional[UploadFile] = File(None)):
    warnings = []
    temp_path = None
    
    try:

        if not file:
            raise HTTPException(
                status_code=400,
                detail="File upload required"
            )
        
        filename = file.filename

        
        content = await file.read()

        
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024}MB"
            )

        
        suffix = Path(filename).suffix or ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(content)
            temp_path = tmp.name
        
        
        features = extract_features(temp_path)
        
        
        static_analysis = run_semgrep_analysis(temp_path)
        if "error" in static_analysis:
            warnings.append(static_analysis["error"])
            static_analysis = []
        
        
        try:
            model = load_model()
            ml_result = predict(model, features)
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            ml_result = {
                "malware": False,
                "score": 0.0,
                "model_version": "v1"
            }
            warnings.append(f"ML prediction unavailable: {str(e)}")
        
        
        # dynamic_result = run_dynamic_analysis(temp_path)
        
        return JSONResponse({
            "filename": filename,
            "static_analysis": static_analysis,
            "features": features,
            "ml_prediction": ml_result,
            # "dynamic_analysis": dynamic_result,
            "warnings": warnings
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temp file {temp_path}: {e}")


@app.post("/analyze-url")
async def analyze_url(url_request: URLRequest):
    warnings = []
    temp_path = None
    
    try:
        url = url_request.url
        filename = url
        

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = response.content
            
            if len(content) > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail=f"Remote file too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024}MB"
                )
            
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(content)
                temp_path = tmp.name
                
        except requests.RequestException as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to download file from URL: {str(e)}"
            )
        
        
        features = extract_features(temp_path)
        
       
        static_analysis = run_semgrep_analysis(temp_path)
        if "error" in static_analysis:
            warnings.append(static_analysis["error"])
            static_analysis = []
        
        
        try:
            model = load_model()
            ml_result = predict(model, features)
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            ml_result = {
                "malware": False,
                "score": 0.0,
                "model_version": "v1"
            }
            warnings.append(f"ML prediction unavailable: {str(e)}")
        
        
        
        return JSONResponse({
            "filename": filename,
            "static_analysis": static_analysis,
            "features": features,
            "ml_prediction": ml_result,
            "dynamic_analysis": dynamic_result,
            "warnings": warnings
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temp file {temp_path}: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)