import asyncio
from core.immune.mutation_engine import mutate, TECHNIQUES
from core.gateway1.pipeline import InputSentinel
from core.gateway1.l1_pattern_engine import PatternEngine
from core.gateway1.l2_sanitizer import Sanitizer
from core.gateway1.l3_ml_classifier import MLClassifier
from core.gateway1.l4_intent_engine import IntentEngine
from core.cache.manager import CacheManager
from core.agentic.decision_layer import AgenticDecisionLayer
from config.settings import get_settings
from core.models import RequestContext, Verdict
import json

async def main():
    settings = get_settings()
    cache = CacheManager(settings)
    cache.initialize()
    agentic = AgenticDecisionLayer(None)
    pattern = PatternEngine(settings.patterns_path)
    pattern.load_patterns()
    sanitizer = Sanitizer()
    ml = MLClassifier(threshold=settings.ml_classifier_threshold)
    ml.load(settings.embedding_model)
    intent = IntentEngine(threshold=settings.intent_similarity_threshold)
    intent.load(settings.embedding_model)
    
    g1 = InputSentinel(cache, agentic, pattern, sanitizer, ml, intent)
    
    with open('data/known_attacks.json') as f:
        seeds = json.load(f)
        
    for seed in seeds[:20]:
        seed_text = seed['text']
        ctx = RequestContext(raw_input=seed_text, is_immune_probe=True)
        ctx = await g1.process(ctx)
        
        if ctx.g1_verdict and ctx.g1_verdict.value == 'BLOCK':
            print(f'Seed {seed["id"]} blocked.')
            for tech in TECHNIQUES.keys():
                mutated = await mutate(seed_text, tech)
                ctx2 = RequestContext(raw_input=mutated, is_immune_probe=True)
                ctx2 = await g1.process(ctx2)
                if not ctx2.g1_verdict or ctx2.g1_verdict.value == 'PASS':
                    print(f'  BYPASS! tech={tech}')

asyncio.run(main())
