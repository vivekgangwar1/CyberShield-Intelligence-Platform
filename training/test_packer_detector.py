
from utils.packer_detector import detect_packer

file_path = input("Enter EXE file path: ").strip().strip('"')

try:
    result = detect_packer(file_path)

    print("\nPacker Detection Result")
    print("-----------------------")
    print("Packer:", result["packer"])
    print("Packer Type:", result["packer_type"])

except Exception as error:
    print("Error:", error)
