from __future__ import annotations

import asyncio
import os
import subprocess
from typing import Optional

import httpx
from langchain_core.tools import tool

from backend.config import settings


@tool
def read_file(path: str) -> str:
    """Read a file from the local filesystem. Provide a relative path within the sandbox directory."""
    # Resolve relative to sandbox
    if not os.path.isabs(path):
        full_path = os.path.join(settings.sandbox_dir, path)
    else:
        full_path = path

    try:
        with open(full_path, "r") as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return f"Error: File not found: {path}"
    except PermissionError:
        return f"Error: Permission denied: {path}"
    except Exception as e:
        return f"Error reading file: {e}"


@tool
def api_call(method: str, url: str, body: Optional[str] = None) -> str:
    """Make an HTTP request. method should be GET or POST. url is the target URL. body is optional request body for POST."""
    try:
        with httpx.Client(timeout=10) as client:
            if method.upper() == "GET":
                resp = client.get(url)
            elif method.upper() == "POST":
                resp = client.post(url, content=body, headers={"Content-Type": "application/json"})
            else:
                return f"Error: Unsupported method: {method}"
            return f"Status: {resp.status_code}\nBody: {resp.text[:500]}"
    except Exception as e:
        return f"Error making API call: {e}"


@tool
def run_shell(command: str) -> str:
    """Execute a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR: {result.stderr}"
        if result.returncode != 0:
            output += f"\nExit code: {result.returncode}"
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 15 seconds"
    except Exception as e:
        return f"Error executing command: {e}"


ALL_TOOLS = [read_file, api_call, run_shell]
