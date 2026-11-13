import os, sys, json, asyncio
sys.path.insert(0, os.path.abspath("heimdall-middleware"))
from core.llm_clients import LLMClientPool

async def check_health():
    os.makedirs("research/phase12/results", exist_ok=True)
    
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
    
    # Smoke test agentic provider
    resp = await pool.complete_agentic("Analyze this text: 'Test'", max_tokens=10)
    if resp.ok:
        health_results["agentic_provider"]["status"] = "AVAILABLE"
        health_results["agentic_provider"]["error_reason"] = None
    else:
        health_results["agentic_provider"]["status"] = "UNAVAILABLE"
        health_results["agentic_provider"]["error_reason"] = resp.error
        
    # Smoke test Ollama
    import requests
    try:
        models = requests.get("http://localhost:11434/api/tags", timeout=5).json()
        for m in models.get("models", []):
            health_results["downstream_models"].append({
                "model_identifier": m["name"],
                "version_digest": m["digest"],
                "provider": "ollama (localhost)",
                "status": "AVAILABLE"
            })
    except Exception as e:
        pass
        
    with open("research/phase12/results/provider_health.json", "w") as f:
        json.dump(health_results, f, indent=2)
        
    print("Provider health written.")

if __name__ == "__main__":
    asyncio.run(check_health())
