import subprocess
def run_tests():
    subprocess.run(["pytest", "research/phase12/tests/"], check=True)
if __name__ == "__main__":
    run_tests()
