import os
import re
path = 'heimdall-middleware/core/agentic/decision_layer.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    'return AgenticDecision.safe_pass()',
    'return AgenticDecision.safe_block("AGENTIC_ERROR_FAIL_CLOSED")'
)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated decision_layer.py to fail closed.")
