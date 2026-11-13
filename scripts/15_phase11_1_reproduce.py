import os
import subprocess

print("Applying necessary Phase 11.1 patches for simulation...")
subprocess.run("python scripts/patch_fail_closed.py", shell=True, check=True)
subprocess.run("python scripts/patch_models_sampling.py", shell=True, check=True)

print("Running Phase 11.1 Reproduction...")
subprocess.run("python scripts/13_phase11_1_validate.py", shell=True, check=True)
subprocess.run("python scripts/13_phase11_1_validate_P0.py", shell=True, check=True)
subprocess.run("python scripts/14_phase11_1_metrics.py", shell=True, check=True)
print("Reproduction complete.")
