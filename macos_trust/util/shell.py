"""Safe subprocess execution utilities."""

import subprocess
from dataclasses import dataclass


@dataclass
class ShellResult:
    """Result from a shell command execution."""
    
    code: int
    out: str
    err: str
    
    @property
    def success(self) -> bool:
        """Check if the command succeeded (exit code 0)."""
        return self.code == 0
    
    def __bool__(self) -> bool:
        """Allow using result in boolean context (True if successful)."""
        return self.success


def run(cmd: list[str], timeout: int = 6) -> ShellResult:
    """
    Execute a command safely without shell interpretation.
    
    Args:
        cmd: Command and arguments as a list of strings (e.g., ['ls', '-la', '/tmp'])
        timeout: Maximum execution time in seconds (default: 6)
    
    Returns:
        ShellResult with exit code, stdout, and stderr
    
    Raises:
        TimeoutError: If command execution exceeds timeout
        FileNotFoundError: If the command executable is not found
    
    Example:
        >>> result = run(['ls', '-la', '/tmp'])
        >>> if result.success:
        ...     print(result.out)
    """
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # Explicit: never use shell=True for security
            check=False   # Don't raise CalledProcessError; we handle exit codes
        )
        
        # Normalize newlines and trim whitespace
        stdout = _normalize_output(completed.stdout)
        stderr = _normalize_output(completed.stderr)
        
        return ShellResult(
            code=completed.returncode,
            out=stdout,
            err=stderr
        )
    
    except subprocess.TimeoutExpired as e:
        # Convert to standard TimeoutError with helpful message
        raise TimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from e


def _normalize_output(text: str) -> str:
    """
    Normalize command output: convert line endings and trim whitespace.
    
    Args:
        text: Raw output from subprocess
    
    Returns:
        Normalized string with consistent line endings and trimmed whitespace
    """
    if not text:
        return ""
    
    # Normalize line endings to \n and strip leading/trailing whitespace
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.strip()
