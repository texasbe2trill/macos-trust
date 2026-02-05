"""Utility functions for running macOS binaries safely."""

import subprocess
from pathlib import Path
from typing import Optional, Dict, Any


class ProcessResult:
    """Encapsulates the result of a subprocess execution."""
    
    def __init__(
        self,
        success: bool,
        stdout: str,
        stderr: str,
        returncode: int,
        error: Optional[str] = None
    ):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "error": self.error
        }


def run_macos_binary(
    binary_path: str,
    args: list[str],
    timeout: int = 10
) -> ProcessResult:
    """
    Run a macOS binary with arguments.
    
    Args:
        binary_path: Full path to the binary (e.g., '/usr/bin/codesign')
        args: List of arguments to pass to the binary
        timeout: Timeout in seconds (default: 10)
    
    Returns:
        ProcessResult object containing execution details
    """
    # Verify the binary exists
    if not Path(binary_path).exists():
        return ProcessResult(
            success=False,
            stdout="",
            stderr="",
            returncode=-1,
            error=f"Binary not found: {binary_path}"
        )
    
    try:
        # Run without shell, directly executing the binary
        result = subprocess.run(
            [binary_path] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit
        )
        
        return ProcessResult(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            error=None
        )
    
    except subprocess.TimeoutExpired:
        return ProcessResult(
            success=False,
            stdout="",
            stderr="",
            returncode=-1,
            error=f"Command timed out after {timeout} seconds"
        )
    
    except Exception as e:
        return ProcessResult(
            success=False,
            stdout="",
            stderr="",
            returncode=-1,
            error=f"Unexpected error: {str(e)}"
        )


def get_macos_version() -> Optional[str]:
    """Get the macOS version using sw_vers."""
    result = run_macos_binary("/usr/bin/sw_vers", ["-productVersion"])
    if result.success:
        return result.stdout.strip()
    return None
