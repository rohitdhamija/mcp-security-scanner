import os
import re
import json
import httpx
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

# Initialize the server
mcp = FastMCP("Security-Toolkit")

# --- Keep all your existing patterns and tools exactly as they are ---

SCAN_EXTENSIONS = (
    ".py", ".js", ".ts", ".json", ".env",
    ".yaml", ".yml", ".txt", ".ini", ".md"
)

PATTERNS = {
    "OpenAI": {"regex": r"sk-[a-zA-Z0-9-]{40,}", "group": 0},
    "Anthropic": {"regex": r"sk-ant-api03-[a-zA-Z0-9\-_]{50,}", "group": 0},
    "Google Gemini": {"regex": r"AIzaSy[a-zA-Z0-9\-_]{30,}", "group": 0},
    "Azure OpenAI Key": {
        "regex": r"(?:api[-_]key|subscription[-_]key|azure[-_]key)\s*[:=]\s*['\"]([a-fA-F0-9]{32})['\"]",
        "group": 1
    },
    "Azure Endpoint": {
        "regex": r"https://[a-zA-Z0-9\-]+\.openai\.azure\.com/?",
        "group": 0
    }
}

def mask_value(value: str) -> str:
    if len(value) <= 12: return value
    return f"{value[:8]}...{value[-4:]}"

@mcp.tool()
def scan_directory(path: str) -> str:
    base_path = os.path.abspath(path)
    if not os.path.exists(base_path):
        return json.dumps({"error": f"Path not found: {base_path}"})
    findings = []
    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "bin", "__pycache__", "dist"}]
        for file in files:
            if not file.endswith(SCAN_EXTENSIONS): continue
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, base_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for provider, rule in PATTERNS.items():
                            for match in re.finditer(rule["regex"], line):
                                raw_value = match.group(rule["group"])
                                findings.append({
                                    "provider": provider,
                                    "file": rel_path,
                                    "line": line_no,
                                    "masked_value": mask_value(raw_value),
                                    "raw_value": raw_value 
                                })
            except Exception as e:
                findings.append({"provider": "FileReadError", "file": rel_path, "error": str(e)})

    return json.dumps({"summary": {"total_detections": len(findings), "scanned_path": base_path}, "findings": findings}, indent=2)

@mcp.tool()
async def validate_key(provider: str, api_key: str, azure_endpoint: str = None) -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "OpenAI":
                resp = await client.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {api_key}"})
            elif provider == "Anthropic":
                resp = await client.get("https://api.anthropic.com/v1/models", headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"})
            elif provider in ("Azure OpenAI", "Azure OpenAI Key"):
                if not azure_endpoint: return json.dumps({"error": "Azure requires an endpoint URL to validate."})
                url = f"{azure_endpoint.rstrip('/')}/openai/models?api-version=2024-02-01"
                resp = await client.get(url, headers={"api-key": api_key})
            else:
                return json.dumps({"error": f"Provider '{provider}' not supported."})
            is_valid = resp.status_code == 200
            return json.dumps({"provider": provider, "is_valid": is_valid, "http_status": resp.status_code}, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

# --- START: RENDER DEPLOYMENT CODE ---

# Create the Starlette app to handle SSE (Server-Sent Events)
# This replaces the old mcp.run() for web-based hosting
app = Starlette(
    routes=[
        Mount("/", app=mcp.sse_app()),
    ]
)

if __name__ == "__main__":
    import uvicorn
    # Local fallback for testing (run: python server.py)
    uvicorn.run(app, host="0.0.0.0", port=8000)