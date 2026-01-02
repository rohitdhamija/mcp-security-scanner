# Contributing to Security-Toolkit MCP 🛡️

First off, thank you for considering contributing! Projects like this thrive on community eyes—especially when it involves security and secret detection.

### 🌟 Ways You Can Help
- **New Patterns**: Add regex patterns for more providers (e.g., AWS, Stripe, Twilio).
- **Validation Logic**: Improve the `validate_key` function for existing or new providers.
- **Bug Fixes**: Help us refine the directory crawler or error handling.
- **Documentation**: Improve the README or add examples of agentic workflows.

---

### 🛠️ Local Development Setup

To test your changes locally before pushing to Render:

1. **Clone your fork**:
   ```bash
   git clone [https://github.com/YOUR-USERNAME/mcp-security-scanner.git](https://github.com/YOUR-USERNAME/mcp-security-scanner.git)
   cd mcp-security-scanner

2. **Set up a virtual environment**:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

3. **Run the server**:
python server.py

The server will start at http://localhost:8000. You can point your mcp.json here to test your new tools in real-time.
   