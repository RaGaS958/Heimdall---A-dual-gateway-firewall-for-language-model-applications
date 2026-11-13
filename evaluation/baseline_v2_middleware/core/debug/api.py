import os
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

from core.models import RequestContext
from core.gateway1.pipeline import InputSentinel
from core.gateway2.pipeline import OutputSentinel

router = APIRouter(prefix="/debug", tags=["debug"])

_g1_instance: Optional[InputSentinel] = None
_g2_instance: Optional[OutputSentinel] = None

def set_gateways(g1, g2):
    global _g1_instance, _g2_instance
    _g1_instance = g1
    _g2_instance = g2

def verify_debug_access(x_admin_key: str):
    if os.getenv("ENABLE_DEBUG_CONSOLE", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="Debug console disabled")
    expected_key = os.getenv("ADMIN_KEY", "guardian-admin-local-dev-only")
    if not expected_key or x_admin_key != expected_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")

class TraceRequest(BaseModel):
    message: str
    mock_llm_response: Optional[str] = None

@router.post("/trace")
async def run_trace(req: TraceRequest, x_admin_key: str = Header(default="")):
    verify_debug_access(x_admin_key)
    if not _g1_instance or not _g2_instance:
        raise HTTPException(status_code=500, detail="Gateways not initialized")
        
    ctx = RequestContext(raw_input=req.message, is_immune_probe=True)
    ctx.trace_data = {"input_stage": [], "output_stage": []}
    
    # Process G1
    ctx = await _g1_instance.process(ctx)
    
    # Process G2 if G1 passed
    if ctx.g1_verdict and ctx.g1_verdict.value == "PASS":
        ctx.llm_raw_output = req.mock_llm_response or "Mocked LLM response."
        ctx = await _g2_instance.process(ctx)
        
    return {
        "input_stage": ctx.trace_data["input_stage"],
        "output_stage": ctx.trace_data["output_stage"],
        "final_verdict": ctx.g2_verdict.value if getattr(ctx, "g2_verdict", None) else ctx.g1_verdict.value if ctx.g1_verdict else "UNKNOWN",
        "total_latency_ms": getattr(ctx, "total_latency_ms", 0)
    }

@router.post("/counterfactual")
async def run_counterfactual(req: TraceRequest, x_admin_key: str = Header(default="")):
    """Minimal-diff counterfactual search"""
    verify_debug_access(x_admin_key)
    if not _g1_instance:
        raise HTTPException(status_code=500, detail="Gateways not initialized")
        
    tokens = req.message.split()
    if not tokens:
        return {"status": "no_tokens"}
        
    def test_payload(payload):
        """Run L1-L4 only"""
        tctx = RequestContext(raw_input=payload, is_immune_probe=True)
        from core.gateway1.pipeline import _run_l2_sync
        from core.gateway1.l1_pattern_engine import run_l1
        from core.gateway1.l3_ml_classifier import run_l3
        from core.gateway1.l4_intent_engine import run_l4
        
        _run_l2_sync(tctx, _g1_instance.sanitizer)
        run_l1(tctx, _g1_instance.pattern)
        run_l3(tctx, _g1_instance.ml)
        run_l4(tctx, _g1_instance.intent)
        
        return tctx.flag_count, tctx.max_severity, tctx.has_critical_flag
        
    base_flags, base_sev, base_crit = test_payload(req.message)
    
    from config.settings import get_settings
    s = get_settings()

    if base_flags < s.agentic_trigger_flag_count and base_sev < s.agentic_trigger_severity and not base_crit:
        return {
            "found": False,
            "note": "Original message is not blocked by deterministic layers. Counterfactual search not needed."
        }

    for i in range(len(tokens)):
        mod_tokens = tokens[:i] + tokens[i+1:]
        mod_text = " ".join(mod_tokens)
        flags, sev, crit = test_payload(mod_text)
        
        if flags < s.agentic_trigger_flag_count and sev < s.agentic_trigger_severity and not crit:
            return {
                "found": True,
                "note": "Skipped agentic/LLM step for speed",
                "removed_tokens": [tokens[i]],
                "minimal_edit": mod_text
            }
            
    if len(tokens) <= 20:
        for i in range(len(tokens)):
            for j in range(i+1, len(tokens)):
                mod_tokens = tokens.copy()
                del mod_tokens[j]
                del mod_tokens[i]
                mod_text = " ".join(mod_tokens)
                flags, sev, crit = test_payload(mod_text)
                
                if flags < s.agentic_trigger_flag_count and sev < s.agentic_trigger_severity and not crit:
                    return {
                        "found": True,
                        "note": "Skipped agentic/LLM step for speed",
                        "removed_tokens": [tokens[i], tokens[j]],
                        "minimal_edit": mod_text
                    }
                    
    return {
        "found": False,
        "note": "Bounded search did not find a counterfactual."
    }
