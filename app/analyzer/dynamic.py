"""Dynamic analysis orchestration."""

import logging
from pathlib import Path
from typing import Dict, Any

from app.sandbox.docker_runner import DockerSandbox

logger = logging.getLogger(__name__)


def run_dynamic_analysis(file_path: str) -> Dict[str, Any]:
    """
    Run dynamic analysis in Docker sandbox.
    
    Args:
        file_path: Path to file to analyze
    
    Returns:
        Dynamic analysis results
    """
    # Check file extension
    suffix = Path(file_path).suffix.lower()
    
    # Only run Python files and text files
    runnable_extensions = {'.py', '.txt', '.sh'}
    
    if suffix not in runnable_extensions:
        return {
            "ran": False,
            "reason": f"File type {suffix} not supported for dynamic analysis"
        }
    
    # Initialize sandbox
    sandbox = DockerSandbox()
    
    # Check if Docker is available
    if not sandbox.is_docker_available():
        return {
            "ran": False,
            "reason": "Docker not available"
        }
    
    # Run in sandbox
    try:
        result = sandbox.run(file_path)
        return result
    except Exception as e:
        logger.error(f"Dynamic analysis failed: {e}")
        return {
            "ran": False,
            "reason": f"Execution failed: {str(e)}"
        }