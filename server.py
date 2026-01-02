import os
import re
import json
import httpx
from fastmcp import FastMCP

# Initialize the server
mcp = FastMCP("Security-Toolkit")

# File types worth scanning (helps performance by skipping images/binaries)
SCAN_EXTENSIONS = (
    ".py", ".js", ".ts", ".json", ".env",
    ".yaml", ".yml", ".txt", ".ini", ".md"
)

# Detection patterns
PATTERNS = {
    "OpenAI": {
        "regex": r"sk-[a-zA-Z0-9-]{40,}", # Catches legacy and new project keys
        "group": 0
    },
    "Anthropic": {
        "regex": r"sk-ant-api03-[a-zA-Z0-9\-_]{50,}",
        "group": 0
    },
    "Google Gemini": {
        "regex": r"AIzaSy[a-zA-Z0-9\-_]{30,}",
        "group": 0
    },
    "Azure OpenAI Key": {
        # Strictly 32-char hex following a key-related variable name
        "regex": r"(?:api[-_]key|subscription[-_]key|azure[-_]key)\s*[:=]\s*['\"]([a-fA-F0-9]{32})['\"]",
        "group": 1
    },
    "Azure Endpoint": {
        "regex": r"https://[a-zA-Z0-9\-]+\.openai\.azure\.com/?",
        "group": 0
    }
}

def mask_value(value: str) -> str:
    """Masks keys so they are safe to show in the chat UI."""
    if len(value) <= 12:
        return value
    return f"{value[:8]}...{value[-4:]}"

@mcp.tool()
def scan_directory(path: str) -> str:
    """
    Scan a directory for exposed LLM keys and Azure endpoints.
    Returns a detailed JSON report of all matches found.
    """
    base_path = os.path.abspath(path)

    if not os.path.exists(base_path):
        return json.dumps({"error": f"Path not found: {base_path}"})

    findings = []

    for root, dirs, files in os.walk(base_path):
        # Skip heavy/internal folders to keep the scan fast
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "bin", "__pycache__", "dist"}]

        for file in files:
            if not file.endswith(SCAN_EXTENSIONS):
                continue

            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, base_path)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for provider, rule in PATTERNS.items():
                            # finditer catches multiple keys if they exist on the same line
                            for match in re.finditer(rule["regex"], line):
                                raw_value = match.group(rule["group"])
                                findings.append({
                                    "provider": provider,
                                    "file": rel_path,
                                    "line": line_no,
                                    "masked_value": mask_value(raw_value),
                                    "raw_value": raw_value # Kept for the AI to use in validate_key
                                })
            except Exception as e:
                findings.append({
                    "provider": "FileReadError",
                    "file": rel_path,
                    "error": str(e)
                })

    return json.dumps({
        "summary": {
            "total_detections": len(findings),
            "scanned_path": base_path
        },
        "findings": findings
    }, indent=2)

@mcp.tool()
async def validate_key(
    provider: str,
    api_key: str,
    azure_endpoint: str = None
) -> str:
    """
    Validate an API key by making a live metadata request to the provider.
    For Azure, the azure_endpoint URL is required.
    """
    # Using a 10s timeout to prevent the MCP server from hanging
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "OpenAI":
                resp = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"}
                )
            elif provider == "Anthropic":
                # Using the models endpoint for Anthropic validation
                resp = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01"
                    }
                )
            elif provider in ("Azure OpenAI", "Azure OpenAI Key"):
                if not azure_endpoint:
                    return json.dumps({"error": "Azure requires an endpoint URL to validate."})
                
                url = f"{azure_endpoint.rstrip('/')}/openai/models?api-version=2024-02-01"
                resp = await client.get(url, headers={"api-key": api_key})
            else:
                return json.dumps({"error": f"Provider '{provider}' not supported for live validation."})

            # Check for success
            is_valid = resp.status_code == 200
            
            return json.dumps({
                "provider": provider,
                "is_valid": is_valid,
                "http_status": resp.status_code,
                "message": "Key is active" if is_valid else "Key rejected by provider"
            }, indent=2)

        except Exception as e:
            return json.dumps({"error": f"Network/Connection error: {str(e)}"})

if __name__ == "__main__":
    mcp.run("sse")