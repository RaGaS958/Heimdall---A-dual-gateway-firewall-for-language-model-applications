"""
HEIMDALL Phase 3 — Research API

FastAPI router exposing experiment registry, metrics, and results.

All endpoints serve data from stored experiment results.
No metric values are hardcoded or invented in this API.
No endpoints return fabricated data.

Endpoints:
  GET  /research/experiments                 — list all experiments (all statuses)
  GET  /research/experiments/{id}            — experiment detail + metrics
  GET  /research/experiments/{id}/cases      — paginated case-level results
  GET  /research/experiments/{id}/summary    — computed metrics + summary
  GET  /research/overview                    — aggregated dashboard stats
  GET  /research/comparison                  — compare two experiments
  POST /research/experiments/{id}/export     — trigger export (JSON or CSV)
"""
from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter(prefix="/research", tags=["research"])

RESULTS_BASE = "research/results"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_registry():
    from research.experiments.registry import get_registry
    return get_registry()


def _load_metrics_file(experiment_id: str) -> dict:
    path = os.path.join(RESULTS_BASE, "metrics", experiment_id, "metrics.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _load_cases_file(experiment_id: str) -> list[dict]:
    norm_path = os.path.join(RESULTS_BASE, "normalized", experiment_id, "normalized.json")
    if os.path.exists(norm_path):
        with open(norm_path) as f:
            return json.load(f)
    raw_path = os.path.join(RESULTS_BASE, "raw", experiment_id, "cases.jsonl")
    if not os.path.exists(raw_path):
        return []
    cases = []
    with open(raw_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    cases.append(json.loads(line))
                except Exception:
                    pass
    return cases


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/experiments")
async def list_experiments(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List all experiments in the registry.
    Includes ALL statuses: CREATED, RUNNING, COMPLETED, FAILED, PARTIAL.
    FAILED experiments are never hidden.
    """
    registry = _get_registry()
    if status:
        records = registry.list_by_status(status.upper())
    else:
        records = registry.list_all()

    return {
        "total": len(records),
        "experiments": [r.to_dict() for r in records[:limit]],
    }


@router.get("/experiments/{experiment_id}")
async def get_experiment(experiment_id: str):
    """
    Get full details of one experiment: config, status, provenance, and metrics.
    """
    registry = _get_registry()
    record = registry.get(experiment_id)
    if not record:
        raise HTTPException(404, f"Experiment {experiment_id} not found")

    metrics = _load_metrics_file(experiment_id)
    result = record.to_dict()
    result["metrics"] = metrics.get("metrics", {})
    result["metric_version"] = metrics.get("metric_version", "metrics_v1")
    result["computed_at"] = metrics.get("computed_at")
    result["duration_seconds"] = metrics.get("duration_seconds")

    return result


@router.get("/experiments/{experiment_id}/cases")
async def get_experiment_cases(
    experiment_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    expected_behavior: Optional[str] = None,
    attack_outcome: Optional[str] = None,
    is_error: Optional[bool] = None,
):
    """
    Get paginated case-level results for an experiment.
    Raw responses are NOT returned (they contain potentially sensitive payload echoes).
    """
    registry = _get_registry()
    if not registry.get(experiment_id):
        raise HTTPException(404, f"Experiment {experiment_id} not found")

    cases = _load_cases_file(experiment_id)

    # Apply filters
    if expected_behavior:
        cases = [c for c in cases if c.get("expected_behavior") == expected_behavior.upper()]
    if attack_outcome:
        cases = [c for c in cases if c.get("attack_outcome") == attack_outcome.upper()]
    if is_error is not None:
        cases = [c for c in cases if c.get("is_error") == is_error]

    total = len(cases)
    start = (page - 1) * page_size
    end   = start + page_size
    page_cases = cases[start:end]

    # Strip raw_response (security: don't serve raw attack payload echoes)
    for c in page_cases:
        c.pop("raw_response", None)

    return {
        "experiment_id": experiment_id,
        "total": total,
        "page": page,
        "page_size": page_size,
        "cases": page_cases,
    }


@router.get("/experiments/{experiment_id}/summary")
async def get_experiment_summary(experiment_id: str):
    """Get computed metrics and summary statistics for an experiment."""
    registry = _get_registry()
    if not registry.get(experiment_id):
        raise HTTPException(404, f"Experiment {experiment_id} not found")

    metrics_data = _load_metrics_file(experiment_id)
    if not metrics_data:
        raise HTTPException(
            404,
            "Metrics not yet computed for this experiment. "
            "Run the experiment to completion first."
        )

    return metrics_data


@router.get("/overview")
async def get_overview():
    """
    Aggregated dashboard statistics across all COMPLETED experiments.

    Returns counts by status, mean ASR/FPR/DR across all completed experiments,
    and experiment timeline. All numbers derived from stored results only.
    """
    registry = _get_registry()
    counts = registry.count_by_status()
    records = registry.list_all()

    completed = [r for r in records if r.status == "COMPLETED"]
    failed    = [r for r in records if r.status == "FAILED"]
    partial   = [r for r in records if r.status == "PARTIAL"]

    # Aggregate metrics across completed experiments
    asr_values, fpr_values, dr_values = [], [], []
    for r in completed:
        m = _load_metrics_file(r.experiment_id)
        metrics = m.get("metrics", {})
        if "ASR" in metrics and metrics["ASR"].get("value") is not None:
            asr_values.append(metrics["ASR"]["value"])
        if "FPR" in metrics and metrics["FPR"].get("value") is not None:
            fpr_values.append(metrics["FPR"]["value"])
        if "DR" in metrics and metrics["DR"].get("value") is not None:
            dr_values.append(metrics["DR"]["value"])

    def _mean_or_none(vals):
        return round(sum(vals) / len(vals), 4) if vals else None

    return {
        "counts_by_status": counts,
        "total_experiments": len(records),
        "completed": len(completed),
        "failed": len(failed),
        "partial": len(partial),
        "aggregate_metrics": {
            "mean_asr": _mean_or_none(asr_values),
            "mean_fpr": _mean_or_none(fpr_values),
            "mean_dr":  _mean_or_none(dr_values),
            "n_experiments_with_asr": len(asr_values),
            "note": (
                "Aggregated across all COMPLETED experiments. "
                "Experiments may have different configurations. "
                "Do not interpret as a single controlled comparison."
            ),
        },
        "recent_experiments": [r.to_dict() for r in records[:10]],
    }


@router.get("/comparison")
async def compare_experiments(
    exp_a: str = Query(..., description="First experiment ID"),
    exp_b: str = Query(..., description="Second experiment ID"),
):
    """
    Compare two experiments.
    Performs compatibility checks before returning metric differences.
    Incompatible dimensions are flagged NOT_DIRECTLY_COMPARABLE.
    """
    registry = _get_registry()

    record_a = registry.get(exp_a)
    record_b = registry.get(exp_b)

    if not record_a:
        raise HTTPException(404, f"Experiment {exp_a} not found")
    if not record_b:
        raise HTTPException(404, f"Experiment {exp_b} not found")

    try:
        config_a = json.loads(record_a.config_json)
    except Exception:
        config_a = {}
    try:
        config_b = json.loads(record_b.config_json)
    except Exception:
        config_b = {}

    # Compatibility checks
    def get(cfg, *keys):
        val = cfg
        for k in keys:
            val = val.get(k, "MISSING") if isinstance(val, dict) else "MISSING"
        return val

    checks = []
    is_comparable = True
    for dim, keys, critical in [
        ("dataset.name",           ("dataset", "name"),          True),
        ("dataset.version",        ("dataset", "version"),        True),
        ("evaluation.metric_version", ("evaluation", "metric_version"), True),
        ("model.provider",         ("model", "provider"),         True),
        ("evaluation.random_seed", ("evaluation", "random_seed"), False),
        ("defense.baseline",       ("defense", "baseline"),       False),
    ]:
        va = get(config_a, *keys)
        vb = get(config_b, *keys)
        match = va == vb
        if not match and critical:
            is_comparable = False
        checks.append({
            "dimension": dim,
            "exp_a": va,
            "exp_b": vb,
            "match": match,
            "status": "MATCH" if match else ("NOT_DIRECTLY_COMPARABLE" if critical else "DIFFER"),
        })

    metrics_a = _load_metrics_file(exp_a).get("metrics", {})
    metrics_b = _load_metrics_file(exp_b).get("metrics", {})

    diffs = {}
    for name in sorted(set(list(metrics_a.keys()) + list(metrics_b.keys()))):
        ma = metrics_a.get(name, {})
        mb = metrics_b.get(name, {})
        va = ma.get("value")
        vb = mb.get("value")
        diff = None
        if va is not None and vb is not None:
            diff = round(vb - va, 6)
        diffs[name] = {
            "exp_a_value": va,
            "exp_b_value": vb,
            "difference": diff,
            "exp_a_n": ma.get("n"),
            "exp_b_n": mb.get("n"),
            "unit": ma.get("unit", mb.get("unit")),
            "comparable": is_comparable,
        }

    return {
        "exp_a": exp_a,
        "exp_b": exp_b,
        "is_directly_comparable": is_comparable,
        "compatibility_checks": checks,
        "metric_differences": diffs,
        "warning": (
            None if is_comparable
            else "These experiments have incompatible configurations. "
                 "Metric differences should NOT be interpreted as valid comparisons."
        ),
    }


@router.post("/experiments/{experiment_id}/export")
async def export_experiment(
    experiment_id: str,
    format: str = Query("json", description="Export format: json or csv"),
):
    """
    Export experiment results. Secrets are redacted before export.
    """
    registry = _get_registry()
    if not registry.get(experiment_id):
        raise HTTPException(404, f"Experiment {experiment_id} not found")

    try:
        from research.scripts.export_results import export_json, export_csv
        out_dir = "research/exports"

        if format == "json":
            path = export_json(experiment_id, out_dir, registry)
        elif format == "csv":
            path = export_csv(experiment_id, out_dir, registry)
        else:
            raise HTTPException(400, f"Unsupported format: {format}")

        return {"status": "exported", "file": path, "format": format}
    except Exception as e:
        raise HTTPException(500, f"Export failed: {e}")
