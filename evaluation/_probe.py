"""Worker: score one middleware checkout against a suite. Run by run_gateway_eval.py."""
import asyncio, json, os, sys, time

middleware, suite_path, out_path = sys.argv[1:4]
os.chdir(middleware)
sys.path.insert(0, middleware)
os.environ.setdefault("EMBEDDINGS_ENABLED", "false")
os.environ.setdefault("USE_FAKE_REDIS", "true")
from loguru import logger
logger.remove()

from core.models import RequestContext  # noqa: E402
from core.gateway1.l1_pattern_engine import PatternEngine, run_l1  # noqa: E402
from core.gateway1.l2_sanitizer import Sanitizer, run_l2  # noqa: E402
from core.gateway1.l3_ml_classifier import MLClassifier, run_l3  # noqa: E402
from core.gateway1.l4_intent_engine import IntentEngine, run_l4  # noqa: E402

pattern = PatternEngine("patterns/injection_patterns.yaml"); pattern.load_patterns()
ml = MLClassifier(threshold=0.70)
try:
    if hasattr(ml, "lexical"):
        ml.load()
except Exception:
    pass
intent = IntentEngine(threshold=0.75)
sanitizer = Sanitizer()
rows = [json.loads(l) for l in open(suite_path, encoding="utf-8") if l.strip()]
results = []
for row in rows:
    ctx = RequestContext(raw_input=row["text"])
    t0 = time.perf_counter()
    run_l2(ctx, sanitizer); run_l1(ctx, pattern); run_l3(ctx, ml); run_l4(ctx, intent)
    ms = (time.perf_counter() - t0) * 1000
    hard = bool(ctx.has_critical_flag or ctx.flag_count >= 2 or ctx.max_severity >= 7)
    results.append({"id": row["id"], "suite": row["suite"], "label": row["label"], "group": row.get("group", ""),
                    "intercepted": hard, "any_flag": ctx.flag_count > 0, "flags": ctx.flag_count,
                    "max_severity": ctx.max_severity, "latency_ms": round(ms, 3)})
json.dump(results, open(out_path, "w"))
