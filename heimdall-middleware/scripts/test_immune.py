import asyncio
import json
import httpx
import os
import sys

from core.models import RequestContext
from core.immune.api import get_db

async def run_test():
    # We will trigger the campaign via HTTP if the server is running,
    # OR we can just instantiate the pipeline directly.
    # It's easier to instantiate the pipeline directly to show the test.
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    from config.settings import get_settings
    from core.cache.manager import CacheManager
    from core.agentic.decision_layer import AgenticDecisionLayer
    from core.gateway1.l1_pattern_engine import PatternEngine
    from core.gateway1.l2_sanitizer import Sanitizer
    from core.gateway1.l3_ml_classifier import MLClassifier
    from core.gateway1.l4_intent_engine import IntentEngine
    from core.gateway1.pipeline import InputSentinel
    from core.llm_clients import LLMClientPool
    from core.immune.campaign_runner import run_campaign
    
    settings = get_settings()
    
    print("Loading models and engines...")
    cache = CacheManager(settings)
    cache.initialize()
    
    pool = LLMClientPool(settings)
    class MockAgentic:
        async def decide_input(self, ctx):
            from core.models import AgenticDecision, Verdict
            return AgenticDecision(verdict=Verdict.PASS, confidence=0.8, reason="Mocked pass")
    agentic = MockAgentic()
    
    pattern = PatternEngine(settings.patterns_path)
    pattern.load_patterns()
    sanitizer = Sanitizer()
    
    ml = MLClassifier(threshold=settings.ml_classifier_threshold)
    ml.load(settings.embedding_model)
    
    intent = IntentEngine(threshold=settings.intent_similarity_threshold)
    intent.load(settings.embedding_model)
    
    g1 = InputSentinel(cache, agentic, pattern, sanitizer, ml, intent)
    
    print("Stats before:", g1.stats)
    
    # Let's pick 5 seeds
    seed_ids = ["atk_001", "atk_002", "atk_003", "atk_004", "atk_005"]
    techniques = ["case_mutation", "whitespace_mutation", "homoglyph_substitution", "synonym_substitution", "sentence_reorder", "reverse_wrap"]
    
    print(f"Running campaign with seeds: {seed_ids} and techniques: {techniques}...")
    await run_campaign(g1, seed_ids, techniques, n_per_technique=2)
    
    print("Campaign finished.")
    print("Stats after:", g1.stats)
    
    # Read coverage
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT technique, COUNT(*) as total, SUM(CASE WHEN bypassed=1 THEN 1 ELSE 0 END) as bypassed
        FROM mutations
        GROUP BY technique
    ''')
    rows = c.fetchall()
    print("\n--- COVERAGE MATRIX ---")
    for r in rows:
        rate = r['bypassed'] / r['total'] if r['total'] > 0 else 0.0
        print(f"Technique: {r['technique']:25s} | Bypassed: {r['bypassed']}/{r['total']} | Bypass Rate: {rate*100:.1f}%")
        
    c.execute('SELECT * FROM proposals WHERE status = "PENDING" LIMIT 1')
    p = c.fetchone()
    if p:
        print(f"\n--- APPROVING PROPOSAL {p['id']} ---")
        from core.immune.api import approve_proposal, set_g1
        set_g1(g1)
        await approve_proposal(p['id'], x_admin_key="guardian-admin-local-dev-only")
        
        print("\n--- RE-RUNNING THE SAME MUTATION ---")
        mutated_text = p['mutated_text']
        ctx = RequestContext(raw_input=mutated_text, is_immune_probe=True)
        ctx = await g1.process(ctx)
        print(f"Verdict after approval: {ctx.g1_verdict.value}")
        print(f"Flags after approval: {ctx.flag_count}")
        
    conn.close()

if __name__ == "__main__":
    asyncio.run(run_test())
