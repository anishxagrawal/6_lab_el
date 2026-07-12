import subprocess
import shutil
import os
from typing import Optional

class CodeQLExecutionError(Exception):
    """Raised when CodeQL fails to execute a command."""
    pass

def check_codeql_available() -> bool:
    """Check if CodeQL CLI is in system path."""
    return shutil.which("codeql") is not None

def run_codeql_db_create(repo_path: str, db_path: str, language: str) -> None:
    """Create CodeQL database for the repository."""
    if not check_codeql_available():
        raise CodeQLExecutionError("CodeQL CLI is not installed on the system.")
    
    cmd = [
        "codeql", "database", "create", db_path,
        f"--language={language}",
        f"--source-root={repo_path}",
        "--overwrite"
    ]
    # For interpreted/scripting languages, bypass compiling (autobuilder)
    if language.lower() in ["python", "javascript", "ruby"]:
        if os.name == "nt":
            cmd.extend(["--command", "cmd.exe /c type NUL"])
        else:
            cmd.extend(["--command", "true"])
        
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"CODEQL: Database created successfully: {res.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"CODEQL ERROR: Failed to create database: {e.stderr}")
        raise CodeQLExecutionError(f"Database creation failed: {e.stderr}")

def run_codeql_analyze(db_path: str, pack: str, sarif_path: str) -> None:
    """Analyze the database and output SARIF results."""
    if not check_codeql_available():
        raise CodeQLExecutionError("CodeQL CLI is not installed on the system.")

    cmd = [
        "codeql", "database", "analyze", db_path,
        pack,
        "--format=sarif-latest",
        f"--output={sarif_path}"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"CODEQL: Database analyzed successfully: {res.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"CODEQL ERROR: Failed to analyze database: {e.stderr}")
        raise CodeQLExecutionError(f"Database analysis failed: {e.stderr}")
