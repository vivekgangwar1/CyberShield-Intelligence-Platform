
from utils.pe_feature_extractor import extract_basic_pe_info

file_path = input("Enter EXE file path: ").strip().strip('"')

try:
    result = extract_basic_pe_info(file_path)

    print("\nPE FEATURE EXTRACTION RESULT")
    print("=" * 45)

    print("Total extracted features:", len(result))

    for name, value in result.items():
        print(f"{name}: {value}")

except Exception as error:
    print("Error:", error)
