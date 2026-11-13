import os, glob

def fix_newlines():
    files = glob.glob("research/phase12/results/case_results_*.jsonl")
    for file in files:
        with open(file, "r") as f:
            content = f.read()
        
        # Replace literal \n that aren't inside the JSON (actually, json.dumps escapes newlines inside strings as \\n too!)
        # Wait, if json.dumps escapes newlines in strings, it outputs literal \n.
        # But here, between the JSON objects, there is a literal \n.
        # We can just split by "}\n{" and replace with "}\n{"!
        # Actually, since it's `f.write(json.dumps(r) + "\\n")`, it wrote:
        # {"a": 1}\n{"b": 2}\n
        content = content.replace('}\\n{', '}\n{')
        if content.endswith('\\n'):
            content = content[:-2] + '\n'
            
        with open(file, "w") as f:
            f.write(content)
            
    print("Fixed individual files.")
    
    # Merge jsonls
    all_lines = []
    for cond in ["P0", "P1", "P2-0", "P2-10", "P2-25", "P2-50", "P2-100", "ABLATION_L1", "ABLATION_L2", "ABLATION_L3", "ABLATION_L4"]:
        path = f"research/phase12/results/case_results_{cond}.jsonl"
        if os.path.exists(path):
            with open(path, "r") as f:
                all_lines.extend(f.readlines())
                
    with open("research/phase12/results/case_results.jsonl", "w") as f:
        for line in all_lines:
            if not line.endswith('\n'):
                line += '\n'
            f.write(line)
            
    print("Fixed case_results.jsonl")

if __name__ == "__main__":
    fix_newlines()
