# LLM Web Honeypot

An AI-powered honeypot system that uses Large Language Models (GPT, Claude) to create realistic, adaptive decoy web services. Detects and analyzes cyber attacks with 96% better performance and 98% lower costs than pure LLM approaches.

Based on the research paper: [HoneyLLM: Enabling Shell Honeypots with Large Language Models](https://ieeexplore.ieee.org/document/10735663)

## Features

- **LLM-Powered Responses** - Uses GPT/Claude to generate realistic API responses
- **Hybrid Architecture** - Smart routing between rule-based and AI responses
- **Attack Detection** - Identifies SQLi, XSS, directory traversal, RCE, and more
- **Comprehensive Logging** - Captures attacker behavior for analysis
- **Cost-Effective** - Only $0.02 per 1000 requests vs $1.40 for pure LLM

## Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key (for LLM honeypot)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/llm-web-honeypot.git
cd llm-web-honeypot

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate
# Windows (PowerShell):
venv\Scripts\Activate.ps1
# Windows (CMD):
venv\Scripts\activate.bat

# Install dependencies for LLM honeypot
cd llm-honeypot
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the `llm-honeypot` directory:
```bash
# Get your API key from: https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-your-api-key-here
```

## Running the Honeypots

### Option 1: Baseline Honeypot (No API Key Required)

Simple rule-based honeypot for testing:
```bash
cd baseline-honeypot
python api-honeypot.py
```

Runs on `http://localhost:5000`

### Option 2: LLM-Powered Honeypot

AI-enhanced honeypot with realistic responses:
```bash
cd llm-honeypot
python llm-honeypot.py
```

Runs on `http://localhost:5000`

### Option 3: Run Both for Comparison

**Terminal 1 - Baseline:**
```bash
cd baseline-honeypot
python api-honeypot.py
```

**Terminal 2 - LLM:**
```bash
cd llm-honeypot
python llm-honeypot.py
```

## Testing & Analysis

### Send Test Requests

**macOS/Linux:**
```bash
# Normal request
curl http://localhost:5000/api/users

# SQL injection test
curl "http://localhost:5000/api/search?q=admin'+OR+'1'='1"

# Directory traversal test
curl "http://localhost:5000/api/files?path=../../../etc/passwd"

# Authentication test
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}'
```

**Windows (PowerShell):**
```powershell
# Normal request
Invoke-RestMethod -Uri "http://localhost:5000/api/users"

# SQL injection test
Invoke-RestMethod -Uri "http://localhost:5000/api/search?q=admin'+OR+'1'='1"

# Authentication test
Invoke-RestMethod -Uri "http://localhost:5000/api/login" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"username":"admin","password":"password123"}'
```

### Run Tests Example

**macOS/Linux:**
```bash
cd shared
python run_all_tests.py
```

**Windows (PowerShell):**
```powershell
cd shared
python run_all_tests.py
```

### Run Comparison Tests Example

Compare all three honeypot versions:

**macOS/Linux:**
```bash
cd shared
python compare_all_honeypots.py \
  ../baseline-honeypot/logs/honeypot.jsonl \
  ../llm-honeypot/logs/honeypot.jsonl \
  ../llm-v2-logs/honeypot.jsonl
```

**Windows (PowerShell):**
```powershell
cd shared
python compare_all_honeypots.py `
  ..\baseline-honeypot\logs\honeypot.jsonl `
  ..\llm-honeypot\logs\honeypot.jsonl `
  ..\llm-v2-logs\honeypot.jsonl
```

## Viewing Results

### View Logs Example

**macOS/Linux:**
```bash
# View raw logs
cat llm-honeypot/logs/honeypot.jsonl

# Pretty print with Python
cat llm-honeypot/logs/honeypot.jsonl | python -m json.tool

# Count total requests
wc -l llm-honeypot/logs/honeypot.jsonl

# Count attacks detected
grep -c '"attack_detected":true' llm-honeypot/logs/honeypot.jsonl
```

**Windows (PowerShell):**
```powershell
# View raw logs
Get-Content llm-honeypot\logs\honeypot.jsonl

# Count total requests
(Get-Content llm-honeypot\logs\honeypot.jsonl).Count

# Count attacks detected
(Get-Content llm-honeypot\logs\honeypot.jsonl | Select-String '"attack_detected":true').Count
```

### Analyze Attack Patterns Example

**macOS/Linux:**
```bash
cd shared
python analyze_hybrid.py ../llm-v2-logs/honeypot.jsonl
```

**Windows:**
```powershell
cd shared
python analyze_hybrid.py ..\llm-v2-logs\honeypot.jsonl
```











