import re
path = 'heimdall-middleware/core/models.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

patch = """    @property
    def should_escalate_to_agentic(self) -> bool:
        \"\"\"Determine if this request needs the Agentic Decision Layer.\"\"\"
        from config.settings import get_settings
        import random
        import os
        s = get_settings()
        if (
            self.has_critical_flag
            or self.flag_count >= s.agentic_trigger_flag_count
            or self.max_severity >= s.agentic_trigger_severity
            or (self.session and self.session.attack_mode)
        ):
            return True
            
        sampling_rate = float(os.environ.get("AGENTIC_SAMPLING_RATE", "0.0"))
        if sampling_rate > 0 and random.random() < sampling_rate:
            return True
        return False
"""

content = re.sub(r'    @property\n    def should_escalate_to_agentic.*?return False\n', patch, content, flags=re.DOTALL)
with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("models.py patched for configurable sampling.")
