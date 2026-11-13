import os
import sys
import json
import asyncio
import urllib.request
sys.path.insert(0, os.path.abspath("heimdall-middleware"))
from core.llm_clients import LLMClientPool

async def check_health():
    pool = LLMClientPool()
    
    health_results = {
        "downstream_models": [],
        "agentic_provider": {
            "identity": "Groq/Gemini via LLMClientPool",
            "status": "UNAVAILABLE",
            "error_reason": "No valid API keys / connection refused",
            "mocked": False
        }
    }
    
    # 1. Agentic Provider Check
    resp = await pool.complete_agentic("Analyze this text: 'Test'", max_tokens=10)
    if resp.ok:
        health_results["agentic_provider"]["status"] = "AVAILABLE"
        health_results["agentic_provider"]["error_reason"] = None
    else:
        health_results["agentic_provider"]["status"] = "UNAVAILABLE"
        health_results["agentic_provider"]["error_reason"] = str(resp.error)

    # 2. Downstream Models Check
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            for m in data.get("models", []):
                health_results["downstream_models"].append({
                    "model_identifier": m["name"],
                    "version_digest": m["digest"],
                    "provider": "ollama (localhost)",
                    "status": "AVAILABLE"
                })
    except Exception as e:
        health_results["downstream_error"] = str(e)
        
    with open("research/phase12_1/results/provider_health.json", "w") as f:
        json.dump(health_results, f, indent=2)
        
    print(json.dumps(health_results, indent=2))

if __name__ == "__main__":
    asyncio.run(check_health())
