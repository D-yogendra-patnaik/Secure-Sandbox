"""Docker-based sandbox for safe code execution."""

import logging
import os
import platform
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Try to import docker, but handle gracefully if not available
try:
    import docker
    from docker.errors import DockerException
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    logger.warning("Docker SDK not available")


class DockerSandbox:
    """Sandbox for running code in isolated Docker containers."""
    
    def __init__(
        self,
        image: str = "python:3.11-slim",
        memory_limit: str = "256m",
        cpu_quota: int = 50000,  # 0.5 CPU
        timeout: int = 10
    ):
        """
        Initialize Docker sandbox.
        
        Args:
            image: Docker image to use
            memory_limit: Memory limit for container
            cpu_quota: CPU quota (100000 = 1 CPU)
            timeout: Execution timeout in seconds
        """
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.timeout = timeout
        self.client: Optional[Any] = None
        
        if DOCKER_AVAILABLE:
            try:
                # On Windows, use named pipe; on Linux/Mac, use default
                if platform.system() == "Windows":
                    self.client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
                else:
                    self.client = docker.from_env()
            except DockerException as e:
                logger.error(f"Failed to connect to Docker: {e}")
                self.client = None
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available and accessible."""
        if not DOCKER_AVAILABLE or self.client is None:
            return False
        
        try:
            self.client.ping()
            return True
        except Exception as e:
            logger.error(f"Docker ping failed: {e}")
            return False
    
    def run(self, file_path: str) -> Dict[str, Any]:
        """
        Run a file in the Docker sandbox.
        
        Args:
            file_path: Path to file to execute
        
        Returns:
            Execution results with stdout, stderr, exit code, and resources
        """
        if not self.is_docker_available():
            return {
                "ran": False,
                "reason": "Docker not available"
            }
        
        container = None
        
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Determine execution command based on file type
            suffix = Path(file_path).suffix.lower()
            
            if suffix == '.py':
                # Create wrapper script to measure resources
                wrapper = self._create_resource_wrapper(file_content)
                command = ["python", "-c", wrapper]
            elif suffix == '.sh':
                command = ["sh", "-c", file_content.decode('utf-8', errors='ignore')]
            else:
                # For text files, just cat them
                command = ["cat"]
                # We'll pass content via stdin
            
            # Pull image if needed
            try:
                self.client.images.get(self.image)
            except docker.errors.ImageNotFound:
                logger.info(f"Pulling image {self.image}")
                self.client.images.pull(self.image)
            
            # Run container
            start_time = time.time()
            
            container = self.client.containers.run(
                self.image,
                command=command if suffix != '.txt' else ["echo", file_content.decode('utf-8', errors='ignore')[:100]],
                detach=True,
                network_mode="none",  # No network access
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                cpu_period=100000,
                remove=False,
                stdout=True,
                stderr=True
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result.get('StatusCode', -1)
            except Exception:
                # Timeout - kill container
                logger.warning(f"Container execution timed out after {self.timeout}s")
                container.kill()
                exit_code = -1
            
            execution_time = time.time() - start_time
            
            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')
            
            # Get stats (best effort)
            try:
                stats = container.stats(stream=False)
                memory_stats = stats.get('memory_stats', {})
                max_usage = memory_stats.get('max_usage', 0)
                max_rss_mb = max_usage / (1024 * 1024)
            except Exception as e:
                logger.debug(f"Failed to get container stats: {e}")
                max_rss_mb = 0.0
            
            return {
                "ran": True,
                "stdout": stdout[:1000],  # Limit output
                "stderr": stderr[:1000],
                "exit_code": exit_code,
                "resource": {
                    "max_rss_mb": round(max_rss_mb, 2),
                    "cpu_seconds": round(execution_time, 2)
                }
            }
            
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return {
                "ran": False,
                "reason": f"Execution error: {str(e)}"
            }
        finally:
            # Cleanup container
            if container:
                try:
                    container.remove(force=True)
                except Exception as e:
                    logger.error(f"Failed to remove container: {e}")
    
    def _create_resource_wrapper(self, code: bytes) -> str:
        """
        Create a wrapper script that executes code and measures resources.
        
        Args:
            code: Python code to execute
        
        Returns:
            Wrapper script as string
        """
        code_str = code.decode('utf-8', errors='ignore')
        
        # Simple wrapper that executes the code
        wrapper = f"""
import sys
import traceback

try:
    exec('''{code_str}''')
except Exception as e:
    traceback.print_exc()
    sys.exit(1)
"""
        return wrapper