import logging
import os
import sys
import tempfile
from pathlib import Path

# Add current directory to sys.path to support both 'from app.analyzer' and 'from analyzer'
current_dir = Path(__file__).parent.resolve()
if str(current_dir) not in sys.path:
    sys.path.append(str(current_dir))
if str(current_dir.parent) not in sys.path:
    sys.path.append(str(current_dir.parent))
from typing import Optional

import requests
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from analyzer.static import run_semgrep_analysis
from analyzer.dynamic import run_dynamic_analysis
from sandbox.docker_runner import DockerSandbox
from features import extract_features
from model import load_model, predict

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

# Initialize Docker sandbox client lazily
_docker_sandbox = None

def get_docker_sandbox():
    global _docker_sandbox
    if _docker_sandbox is None:
        _docker_sandbox = DockerSandbox()
    return _docker_sandbox

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


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
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.0f}MB"
            )

        suffix = Path(filename).suffix or ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(content)
            temp_path = tmp.name

        features = extract_features(temp_path)

        static_analysis = run_semgrep_analysis(temp_path)
        if isinstance(static_analysis, dict) and "error" in static_analysis:
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

        # ── Dynamic analysis ──────────────────────────────────────────────
        dynamic_result = {}
        try:
            sandbox = get_docker_sandbox()
            if sandbox.is_docker_available():
                logger.info(f"Running Docker-based analysis for {filename}")
                docker_result = sandbox.run(temp_path)
                if docker_result.get("ran"):
                    dynamic_result = {
                        "method": "docker",
                        **docker_result
                    }
                else:
                    logger.warning(f"Docker analysis failed: {docker_result.get('reason')}")
                    # Fallback to local analysis
                    dynamic_result = {
                        "method": "subprocess",
                        **run_dynamic_analysis(temp_path)
                    }
            else:
                # Docker not available - run subprocess-based analysis directly
                logger.info(f"Running subprocess-based analysis for {filename}")
                dynamic_result = {
                    "method": "subprocess",
                    **run_dynamic_analysis(temp_path)
                }
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            dynamic_result = {"error": str(e)}
            warnings.append(f"Dynamic analysis unavailable: {str(e)}")

        # ── 💡 Trustworthiness Scorecard ───────────────────────────────────
        score = 100
        ethics_flags = []
        
        # ML Impact
        if ml_result.get("malware"):
            score -= int(ml_result.get("score", 0) * 50)
            ethics_flags.append(f"ML classified as suspicious (Certainty: {ml_result.get('score')})")
            
        # Static Analysis Impact
        for finding in static_analysis:
            severity = str(finding.get("severity", "INFO")).upper()
            deduction = 10 if severity == "ERROR" else 5
            score -= deduction
            ethics_flags.append(f"Security Policy Violation: {finding.get('message')} [Line {finding.get('start_line')}]")
            
        # Dynamic Analysis Impact
        if dynamic_result.get("risk", {}).get("risk_score"):
            score -= dynamic_result["risk"]["risk_score"]
            ethics_flags.extend([f"Runtime Behavioral Warning: {r}" for r in dynamic_result["risk"].get("reasons", [])])
            
        score = max(0, score)
        scorecard = {
            "trust_score":    score,
            "verdict":        "TRUSTED" if score > 75 else "SUSPICIOUS" if score > 40 else "UNTRUSTED",
            "ethics_layer":   ethics_flags,
            "can_execute":    score > 5
        }

        # Add findings to legacy warnings if empty scorecard
        if not scorecard["ethics_layer"] and not static_analysis and not ml_result.get("malware"):
             warnings.append("No security anomalies detected")

        return JSONResponse({
            "filename":          filename,
            "scorecard":         scorecard,
            "static_analysis":   static_analysis,
            "features":          features,
            "ml_prediction":     ml_result,
            "dynamic_analysis":  dynamic_result,
            "warnings":          warnings
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
                    detail=f"Remote file too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.0f}MB"
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
        if isinstance(static_analysis, dict) and "error" in static_analysis:
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

        # ── Dynamic analysis ──────────────────────────────────────────────
        dynamic_result = {}
        try:
            sandbox = get_docker_sandbox()
            if sandbox.is_docker_available():
                logger.info(f"Running Docker-based analysis for {filename}")
                docker_result = sandbox.run(temp_path)
                if docker_result.get("ran"):
                    dynamic_result = {
                        "method": "docker",
                        **docker_result
                    }
                else:
                    logger.warning(f"Docker analysis failed: {docker_result.get('reason')}")
                    dynamic_result = {
                        "method": "subprocess",
                        **run_dynamic_analysis(temp_path)
                    }
            else:
                logger.info(f"Running subprocess-based analysis for {filename}")
                dynamic_result = {
                    "method": "subprocess",
                    **run_dynamic_analysis(temp_path)
                }
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            dynamic_result = {"error": str(e)}
            warnings.append(f"Dynamic analysis unavailable: {str(e)}")

        # ── 💡 Trustworthiness Scorecard ───────────────────────────────────
        score = 100
        ethics_flags = []
        
        # ML Impact
        if ml_result.get("malware"):
            score -= int(ml_result.get("score", 0) * 50)
            ethics_flags.append(f"ML classified as suspicious (Certainty: {ml_result.get('score')})")
            
        # Static Analysis Impact
        for finding in static_analysis:
            severity = str(finding.get("severity", "INFO")).upper()
            deduction = 10 if severity == "ERROR" else 5
            score -= deduction
            ethics_flags.append(f"Security Policy Violation: {finding.get('message')} [Line {finding.get('start_line')}]")
            
        # Dynamic Analysis Impact
        if dynamic_result.get("risk", {}).get("risk_score"):
            score -= dynamic_result["risk"]["risk_score"]
            ethics_flags.extend([f"Runtime Behavioral Warning: {r}" for r in dynamic_result["risk"].get("reasons", [])])
            
        score = max(0, score)
        scorecard = {
            "trust_score":    score,
            "verdict":        "TRUSTED" if score > 75 else "SUSPICIOUS" if score > 40 else "UNTRUSTED",
            "ethics_layer":   ethics_flags,
            "can_execute":    score > 5
        }

        return JSONResponse({
            "filename":          filename,
            "scorecard":         scorecard,
            "static_analysis":   static_analysis,
            "features":          features,
            "ml_prediction":     ml_result,
            "dynamic_analysis":  dynamic_result,
            "warnings":          warnings
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
    uvicorn.run(app, host="0.0.0.0", port=9000)