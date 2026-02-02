"""Static analysis using Semgrep."""

import json
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Union

logger = logging.getLogger(__name__)

SEMGREP_RULES_PATH = Path(__file__).parent / "semgrep_rules.yml"


def run_semgrep_analysis(file_path: str) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    if not SEMGREP_RULES_PATH.exists():
        logger.warning("Semgrep rules file not found")
        return {"error": "Semgrep rules not configured"}
    
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", str(SEMGREP_RULES_PATH),
                "--json",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        
        if result.returncode not in [0, 1]:
            logger.error(f"Semgrep failed: {result.stderr}")
            return {"error": f"Semgrep execution failed"}
        
        output = json.loads(result.stdout)
        findings = []
        
        for result_item in output.get("results", []):
            findings.append({
                "rule_id": result_item.get("check_id", "unknown"),
                "message": result_item.get("extra", {}).get("message", "No message"),
                "severity": result_item.get("extra", {}).get("severity", "INFO"),
                "start_line": result_item.get("start", {}).get("line", 0),
                "end_line": result_item.get("end", {}).get("line", 0)
            })
        
        return findings
        
    except FileNotFoundError:
        logger.warning("Semgrep not installed")
        return {"error": "Semgrep not installed"}
    except subprocess.TimeoutExpired:
        logger.error("Semgrep analysis timed out")
        return {"error": "Semgrep analysis timed out"}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Semgrep output: {e}")
        return {"error": "Failed to parse Semgrep output"}
    except Exception as e:
        logger.error(f"Semgrep analysis failed: {e}")
        return {"error": f"Semgrep analysis failed: {str(e)}"}