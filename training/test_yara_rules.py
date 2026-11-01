
import yara
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RULE_FILE = BASE_DIR / "utils" / "peid.yara"

try:
    rules = yara.compile(filepath=str(RULE_FILE))
    print("SUCCESS: PEiD YARA rules compiled!")
except Exception as error:
    print("YARA compilation error:")
    print(error)
