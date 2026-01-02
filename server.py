import os
import re
import json
import httpx
from fastmcp import FastMCP, Context
from starlette.applications import Starlette
from starlette.routing import Mount

# Initialize the server
mcp = FastMCP("Security-Toolkit")

SCAN_EXTENSIONS = (".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml", ".txt", ".ini", ".md")

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

def perform_scan(text: str, filename: str = "input"):
    findings = []
    for provider, rule in PATTERNS.items():
        for match in re.finditer(rule["regex"], text):
            raw_value = match.group(rule["group"])
            findings.append({
                "provider": provider,
                "file": filename,
                "masked_value": mask_value(raw_value),
                "raw_value": raw_value 
            })
    return findings

@mcp.tool()
async def smart_scan(target: str, ctx: Context) -> str:
    """
    Scans a local path OR a GitHub URL. 
    If a URL is given, the server will ask the AI to fetch the content automatically.
    """
    # Check if target is a GitHub URL
    if "github.com" in target.lower():
        ctx.info(f"GitHub URL detected. Requesting sampling to fetch content: {target}")
        
        # SAMPLING: The server asks the AI to use its own tools (like GitHub) to get the data
        sample_result = await ctx.sample(
            prompt=f"Please use your GitHub tools to fetch the full content of the file at {target}. I need the raw code to scan for security keys.",
            max_tokens=3000
        )
        
        content = sample_result.text
        findings = perform_scan(content, target)
        return json.dumps({"source": "remote_github", "findings": findings}, indent=2)

    # Standard local directory scan
    return scan_directory(target)

@mcp.tool()
def scan_directory(path: str) -> str:
    base_path = os.path.abspath(path)
    if not os.path.exists(base_path):
        return json.dumps({"error": f"Path not found: {base_path}"})
    
    all_findings = []
    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv"}]
        for file in files:
            if not file.endswith(SCAN_EXTENSIONS): continue
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    all_findings.extend(perform_scan(content, os.path.relpath(file_path, base_path)))
            except Exception as e:
                all_findings.append({"error": f"Read error in {file}: {str(e)}"})

    return json.dumps({"total": len(all_findings), "findings": all_findings}, indent=2)

@mcp.tool()
async def validate_key(provider: str, api_key: str, azure_endpoint: str = None) -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "OpenAI":
                resp = await client.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {api_key}"})
            elif provider == "Anthropic":
                resp = await client.get("https://api.anthropic.com/v1/models", headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"})
            elif provider in ("Azure OpenAI", "Azure OpenAI Key"):
                if not azure_endpoint: return json.dumps({"error": "Azure requires an endpoint URL."})
                url = f"{azure_endpoint.rstrip('/')}/openai/models?api-version=2024-02-01"
                resp = await client.get(url, headers={"api-key": api_key})
            else:
                return json.dumps({"error": f"Provider '{provider}' not supported."})
            return json.dumps({"provider": provider, "is_valid": resp.status_code == 200, "status": resp.status_code}, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

@mcp.prompt()
def audit_repo(repo_url: str):
    """Shortcut: Fetch a repo and scan it for leaks."""
    return f"Use your GitHub tools to explore {repo_url}. Read the main files and pass them to my Security-Toolkit 'smart_scan' tool to check for leaked keys."

app = Starlette(routes=[Mount("/", app=mcp.http_app(transport="sse"))])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)