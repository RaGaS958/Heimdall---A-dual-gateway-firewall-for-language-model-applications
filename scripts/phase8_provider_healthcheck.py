
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../heimdall-middleware")))
from core.llm_clients.mistral import MistralClient

async def main():
    print("--------------------------------------------------")
    print("PHASE 8.1 PROVIDER HEALTH CHECK")
    print("--------------------------------------------------")
    
    provider = "mistral"
    model = "mistral-small-latest"
    env_var = "MISTRAL_API_KEY"
    
    api_key = os.environ.get(env_var, "")
    if not api_key or "your_" in api_key:
        print(f"PROVIDER: {provider}")
        print(f"MODEL: {model}")
        print(f"AUTH: MISSING ({env_var} not found)")
        print(f"STATUS: NOT_READY")
        sys.exit(1)
        
    print(f"PROVIDER: {provider}")
    print(f"MODEL: {model}")
    print(f"AUTH: PRESENT (hidden)")
    
    client = MistralClient(api_key)
    prompt = "Reply with exactly the word OK."
    
    t0 = time.time()
    resp = await client.complete(prompt, system="", max_tokens=10)
    latency = (time.time() - t0) * 1000
    
    if not resp.ok:
        print(f"CONNECTIVITY: ERROR ({resp.error})")
        print(f"GENERATION: FAILED")
        print(f"RESPONSE: NONE")
        print(f"LATENCY: {latency:.1f}ms")
        print(f"STATUS: NOT_READY")
        sys.exit(1)
        
    print(f"CONNECTIVITY: SUCCESS")
    print(f"GENERATION: SUCCESS")
    print(f"RESPONSE: {resp.text.strip()}")
    print(f"LATENCY: {latency:.1f}ms")
    print(f"STATUS: READY")

if __name__ == "__main__":
    asyncio.run(main())

