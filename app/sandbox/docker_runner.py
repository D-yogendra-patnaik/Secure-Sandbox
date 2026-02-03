import logging
import os
import platform
import time
from pathlib import Path
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import docker

logger = logging.getLogger(__name__)


try:
    import docker
    from docker.errors import DockerException, ImageNotFound, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None
    DockerException = Exception  
    ImageNotFound = Exception
    APIError = Exception


class DockerSandbox:
   

    def __init__(
        self,
        image: str = "python:3.11-slim",
        memory_limit: str = "256m",
        cpu_quota: int = 50000,  # 0.5 CPU
        timeout: int = 10
    ):
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.timeout = timeout
        self.client: Optional[Any] = None

        if not DOCKER_AVAILABLE:
            logger.error("Docker SDK not installed")
            return

        try:
            
            if docker is not None:
                self.client = docker.from_env()
                if self.client is not None:
                    self.client.ping()  
                    logger.info("Docker daemon is available")

        except DockerException as e:
            logger.error(f"Docker daemon not reachable: {e}")
            self.client = None

    def is_docker_available(self) -> bool:
        """Return True only if Docker daemon is reachable."""
        return self.client is not None

    def run(self, file_path: str) -> Dict[str, Any]:
        if not self.is_docker_available():
            return {
                "ran": False,
                "reason": "Docker daemon not running or not accessible"
            }

        if self.client is None:
            return {
                "ran": False,
                "reason": "Docker client is not initialized"
            }

        path_obj = Path(file_path).resolve()
        suffix = path_obj.suffix.lower()

        if suffix not in {".py", ".sh", ".txt"}:
            return {
                "ran": False,
                "reason": f"Unsupported file type: {suffix}"
            }

        container = None
        start_time = time.time()

        try:
            try:
                self.client.images.get(self.image)
            except ImageNotFound:
                logger.info(f"Pulling Docker image: {self.image}")
                self.client.images.pull(self.image)

            if suffix == ".py":
                command = ["python", f"/sandbox/{path_obj.name}"]
            elif suffix == ".sh":
                command = ["sh", f"/sandbox/{path_obj.name}"]
            else:
                command = ["cat", f"/sandbox/{path_obj.name}"]


            container = self.client.containers.run(
                image=self.image,
                command=command,
                detach=True,
                network_mode="none",
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                cpu_period=100000,
                volumes={
                    str(path_obj.parent): {
                        "bind": "/sandbox",
                        "mode": "ro"
                    }
                },
                stdout=True,
                stderr=True,
            )

            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result.get("StatusCode", -1)
            except Exception:
                container.kill()
                exit_code = -1

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")

            execution_time = round(time.time() - start_time, 2)

            return {
                "ran": True,
                "exit_code": exit_code,
                "stdout": stdout[:2000],
                "stderr": stderr[:2000],
                "resource": {
                    "cpu_seconds": execution_time
                }
            }

        except APIError as e:
            logger.error(f"Docker API error: {e}")
            return {
                "ran": False,
                "reason": f"Docker API error: {str(e)}"
            }

        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return {
                "ran": False,
                "reason": str(e)
            }

        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
