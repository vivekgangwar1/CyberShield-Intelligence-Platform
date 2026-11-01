
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RULE_FILE = BASE_DIR / "utils" / "peid.yara"

source = RULE_FILE.read_text(
    encoding="utf-8",
    errors="ignore"
)

# Extract YARA rule identifiers
rule_names = re.findall(
    r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)",
    source
)

print("Total YARA rules:", len(rule_names))
print("\nFirst 100 YARA rule names:\n")

for name in rule_names[:100]:
    print(name)
