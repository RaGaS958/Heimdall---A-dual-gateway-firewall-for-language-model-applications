"""L2: token sanitizer. Thin adapter from the pipeline to the canonicalizer."""
from __future__ import annotations

from typing import Optional

from core.models import AttackFamily, Flag, FlagSource, RequestContext

from .canonicalizer import CONFUSABLES as HOMOGLYPHS, CanonicalResult, canonicalize  # noqa: F401


class Sanitizer:
    pass


def run_l2(ctx: RequestContext, sanitizer: Optional[Sanitizer] = None) -> None:
    """Canonicalize the input and raise a flag for each obfuscation technique seen."""
    if ctx.canonical_result is None or ctx.canonical_result.raw != ctx.raw_input:
        ctx.canonical_result = canonicalize(ctx.raw_input)
    result: CanonicalResult = ctx.canonical_result

    ctx.canonical_input = result.canonical
    ctx.llm_safe_input = result.llm_safe
    ctx.normalization_delta = result.delta
    if result.transforms:
        ctx.normalization_applied.extend(result.transforms)

    if not ctx.l2_flags_raised:
        ctx.l2_flags_raised = True
        for signal in result.signals:
            try:
                family = AttackFamily(signal.family)
            except ValueError:
                family = AttackFamily.UNKNOWN
            ctx.add_flag(Flag(source=FlagSource.NORMALIZE, severity=signal.severity,
                              confidence=signal.confidence, attack_families=[family],
                              evidence=f"L2 {signal.name}: {signal.evidence}"))

    ctx.trace_data["input_stage"].append({
        "layer": "L2",
        "transformations": list(result.transforms),
        "views": [name for name, _ in result.scan_views()],
        "before": ctx.raw_input,
        "after": result.canonical,
    })
