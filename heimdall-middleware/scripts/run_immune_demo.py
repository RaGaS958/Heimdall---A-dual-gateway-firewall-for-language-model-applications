import httpx
import time
import json
import asyncio
import os
import sys

# Add parent directory to path so we can import core directly to test G1 directly if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

BASE_URL = "http://localhost:8000"
ADMIN_KEY = "guardian-admin-local-dev-only"

def print_section(title):
    print(f"\n{'='*50}\n{title}\n{'='*50}")

async def main():
    async with httpx.AsyncClient() as client:
        # 1. Check stats before campaign
        print_section("1. Stats BEFORE campaign")
        resp = await client.get(f"{BASE_URL}/stats")
        if resp.status_code != 200:
            print("Failed to get stats. Is the server running?")
            return
        
        before_stats = resp.json()
        print(json.dumps(before_stats['summary'], indent=2))
        
        # 2. Run Campaign
        print_section("2. Running Immune Campaign (5 seeds, 5 techniques)")
        # Get some seeds from known_attacks
        with open("data/known_attacks.json", "r") as f:
            attacks = json.load(f)
            seed_ids = [a["id"] for a in attacks[:5]]
            
        payload = {
            "seed_ids": seed_ids,
            "techniques": [
                "case_mutation", 
                "whitespace_mutation", 
                "homoglyph_substitution", 
                "base64_wrap", 
                "synonym_substitution",
                "reverse_wrap"
            ],
            "n_per_technique": 1
        }
        
        resp = await client.post(
            f"{BASE_URL}/immune/campaign", 
            json=payload,
            headers={"x-admin-key": ADMIN_KEY}
        )
        print("Campaign started:", resp.json())
        
        print("Waiting for campaign to finish (10 seconds)...")
        await asyncio.sleep(10)
        
        # 3. Coverage Map
        print_section("3. Coverage Map")
        resp = await client.get(f"{BASE_URL}/immune/coverage", headers={"x-admin-key": ADMIN_KEY})
        coverage = resp.json()["coverage"]
        print(json.dumps(coverage, indent=2))
        
        # 4. Check proposals
        print_section("4. Pending Proposals")
        resp = await client.get(f"{BASE_URL}/immune/proposals", headers={"x-admin-key": ADMIN_KEY})
        proposals = resp.json()["proposals"]
        print(f"Found {len(proposals)} proposals.")
        if not proposals:
            print("No proposals generated. Maybe no bypasses occurred or the logic failed.")
            return
            
        prop = proposals[0]
        print("First proposal:")
        print(json.dumps(prop, indent=2))
        
        mutated_text = prop["mutated_text"]
        
        # 5. Check if the mutated_text currently bypasses
        print_section("5. Verifying bypassed payload BEFORE approval")
        # Run chat with the payload
        resp = await client.post(
            f"{BASE_URL}/chat", 
            json={"message": mutated_text}
        )
        print(f"G1 Verdict before approval: {resp.json().get('verdict_g1')}")
        
        # 6. Approve proposal
        print_section("6. Approving Proposal")
        resp = await client.post(
            f"{BASE_URL}/immune/proposals/{prop['id']}/approve", 
            headers={"x-admin-key": ADMIN_KEY}
        )
        print(f"Approval status: {resp.status_code} - {resp.json()}")
        
        # 7. Check if the mutated_text is now blocked
        print_section("7. Verifying bypassed payload AFTER approval")
        resp = await client.post(
            f"{BASE_URL}/chat", 
            json={"message": mutated_text}
        )
        print(f"G1 Verdict after approval: {resp.json().get('verdict_g1')}")
        
        # 8. Check stats after campaign
        print_section("8. Stats AFTER campaign (Should be unchanged by the campaign itself)")
        resp = await client.get(f"{BASE_URL}/stats")
        after_stats = resp.json()
        print(json.dumps(after_stats['summary'], indent=2))
        
if __name__ == "__main__":
    asyncio.run(main())
