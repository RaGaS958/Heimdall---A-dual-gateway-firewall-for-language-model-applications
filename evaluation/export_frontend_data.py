#!/usr/bin/env python3
"""Write heimdall-frontend/public/data/evaluation.json from stored results only."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
results = ROOT / "evaluation/results"
held = json.loads((results / "gateway_eval_heldout_run2_after_phase15.json").read_text())
ext = json.loads((results / "gateway_eval_exttest_run1_frozen.json").read_text())
ext0 = json.loads((results / "gateway_eval_exttest_run0_pre_tuning.json").read_text())
extdev = json.loads((results / "gateway_eval_extdev.json").read_text())
dev = json.loads((results / "gateway_eval_dev.json").read_text())


def row(name, entry, status):
    return {"name": name, "status": status, **{k: entry[k] for k in ("n", "before", "after", "gained", "lost", "mcnemar_p", "after_ci")}}


unseen = held["by_group"]["phase12/attack/UNSEEN"]
benign = held["groups"]["phase12/benign"]
ext_attack, ext_benign = ext["groups"]["ext_test/attack"], ext["groups"]["ext_test/benign"]
payload = {
    "external": {"attack": ext_attack, "benign": ext_benign, "pre_tuning_attack": ext0["groups"]["ext_test/attack"]["after"],
                 "pre_tuning_benign": ext0["groups"]["ext_test/benign"]["after"], "latency": ext["latency_after"]},
    "heldout": unseen,
    "benign": benign,
    "latency": {"before": held["latency_before"], "after": held["latency_after"]},
    "conditions": ("Paired on identical inputs. Arbiter unavailable, so a hard signal counts as a block (the Phase 12 P2-0 condition). "
                   "Embedding model not loaded, so L3 runs on its bundled lexical model. Cost is measured on one CPU core: about 2 ms for a "
                   "short prompt, and a 95th percentile near 50 ms on the long prompts of the external benchmark."),
    "rows": [
        row("External benchmark, sealed half, attacks", ext_attack, "Third-party prompts; never opened, scored once after tuning froze"),
        row("External benchmark, sealed half, benign", ext_benign, "Third-party instructions; lower is better"),
        *[row(f"  {name.split('/')[-1].replace('_', ' ')}", entry, "Sealed half, by source") for name, entry in ext["by_group"].items() if "/attack/" in name],
        row("Phase 12 adaptive mutations, attacks", unseen, "Held out; third scoring, text never inspected"),
        row("Phase 12 original seeds, attacks", held["by_group"]["phase12/attack/ORIGINAL"], "Seeds known to earlier rules"),
        row("Phase 12 benign prompts", benign, "Held out; lower is better"),
        row("External benchmark, development half, attacks", extdev["groups"]["ext_dev/attack"], "Used to write rules and train the lexical model"),
        row("External benchmark, development half, benign", extdev["groups"]["ext_dev/benign"], "Used for training; lower is better"),
        row("heimdall_v1, attacks", held["groups"]["heimdall_v1/attack"], "Used for tuning"),
        row("heimdall_v1, benign", held["groups"]["heimdall_v1/benign"], "Used for tuning; lower is better"),
        row("Authored development corpus, attacks", dev["groups"]["dev/attack"], "Rules written against it"),
        row("Authored development corpus, benign", dev["groups"]["dev/benign"], "Includes 168 look-alike prompts; lower is better"),
    ],
    "limits": [
        "Gateway interception, not attack success. A prompt that passes may still fail against the model, and one that is stopped may have failed anyway.",
        "The sealed half comes from the same sources as the half used for tuning (Tensor Trust, garak, Alpaca). It shows the rules and model generalise within those sources, not to attack styles nobody has collected yet.",
        "Some benchmark attacks only make sense inside one application (for example, asking a door-keeper bot to say its pass phrase). A gateway that does not know the application's goal cannot recognise those.",
        "Benign precision is measured on instruction-style prompts. On 52 authored look-alike prompts kept out of training, 1 was wrongly stopped; real chat traffic is more varied than either set.",
        "The lexical model can now raise a strong signal alone above a calibrated score. That threshold was set on out-of-fold data from the tuning half and should be re-checked on production traffic.",
        "The Phase 12 set has now been scored three times (39, 46, then 50 of 60). No prompt text was inspected, but repeated scoring makes it weaker evidence than the sealed external half.",
        "The arbiter's semantic accuracy is unmeasured. No provider keys were available for this evaluation.",
        "The embedding-based tier was not exercised on this host, so its thresholds are uncalibrated.",
    ],
    "phase_record": [
        {"phase": "Phase 7", "finding": "External reproduction audit corrected earlier overstated results."},
        {"phase": "Phase 8", "finding": "Agentic integrity audit bound arbiter blocks to verified live inference."},
        {"phase": "Phase 9", "finding": "Disabling L1 raised bypass from 3 of 52 to 50 of 52; benign false positives were 5 of 17."},
        {"phase": "Phase 11", "finding": "Rule patches closed known seeds but not adaptive mutations."},
        {"phase": "Phase 12", "finding": "End-to-end: 0 of 100 benign blocked, 35 of 72 attacks succeeded on qwen2.5:0.5b before patches, 32 of 72 after."},
        {"phase": "Phase 12.1", "finding": "Cross-model checks were preliminary, n=10, with benign canary echo on llama3.2:1b."},
        {"phase": "Phase 13", "finding": "Metric contract frozen; invalid pooled figures excluded."},
        {"phase": "Phase 14", "finding": "Manuscript classified READY_WITH_LIMITATIONS, with 19 claims mapped to evidence."},
        {"phase": "Phase 15", "finding": f"First third-party benchmark. Sealed half: {ext_attack['after']} of {ext_attack['n']} attacks stopped (was {ext0['groups']['ext_test/attack']['after']} before tuning on the other half), {ext_benign['after']} of {ext_benign['n']} benign stopped."},
    ],
}
out = ROOT / "heimdall-frontend/public/data/evaluation.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(payload, indent=1))
print("wrote", out)
