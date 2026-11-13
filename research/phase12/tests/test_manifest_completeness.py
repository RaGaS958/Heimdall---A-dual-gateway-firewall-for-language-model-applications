import json, os, pytest

def test_manifest_completeness():
    # Only test if results exist
    if not os.path.exists("research/phase12/results/run_manifest.json"):
        pytest.skip("No manifest yet.")
        
    with open("research/phase12/results/run_manifest.json", "r") as f:
        manifest = json.load(f)
        
    assert "configurations" in manifest
    assert "models" in manifest
    assert "git_commit" in manifest
