
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Union

logger = logging.getLogger(__name__)

SEMGREP_RULES_PATH = Path(__file__).parent / "semgrep_rules.yml"


def _get_semgrep_command() -> str:
    import shutil
    import platform
    import os

    # Try standard system path
    cmd = shutil.which("semgrep")
    if cmd:
        return cmd

    # Try common Windows roaming path
    if platform.system() == "Windows":
        roaming_scripts = Path(os.path.expandvars("%APPDATA%")) / "Python" / "Python314" / "Scripts" / "semgrep.exe"
        if roaming_scripts.exists():
            return str(roaming_scripts)
        
        # Try local scripts
        local_scripts = Path(os.path.expandvars("%LOCALAPPDATA%")) / "Python" / "Python314" / "Scripts" / "semgrep.exe"
        if local_scripts.exists():
            return str(local_scripts)
            
    return "semgrep"


def run_semgrep_analysis(file_path: str) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    if not SEMGREP_RULES_PATH.exists():
        logger.warning(f"Semgrep rules file not found at {SEMGREP_RULES_PATH}")
        return {"error": "Semgrep rules not configured"}
    
    semgrep_cmd = _get_semgrep_command()
    logger.info(f"Running Semgrep analysis using {semgrep_cmd} on {file_path}")

    try:
        # Prepare environment with the scripts directory in PATH so semgrep can find pysemgrep
        env = os.environ.copy()
        if semgrep_cmd and os.path.isabs(semgrep_cmd):
            scripts_dir = str(Path(semgrep_cmd).parent)
            env["PATH"] = scripts_dir + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            [
                semgrep_cmd,
                "--config", str(SEMGREP_RULES_PATH),
                "--json",
                file_path
            ],
            env=env,
            capture_output=True,
            encoding='utf-8',
            errors='replace',
            timeout=30,
            check=False
        )
        
        if result.returncode not in [0, 1]:
            logger.error(f"Semgrep failed (returncode {result.returncode}): {result.stderr}")
            return {"error": f"Semgrep execution failed"}
        
        logger.info(f"Semgrep finished with returncode {result.returncode}")
        
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