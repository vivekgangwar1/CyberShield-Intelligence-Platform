
import pefile

file_path = input("Enter EXE file path: ").strip().strip('"')

try:
    pe = pefile.PE(file_path)

    print("\nFILEINFO VERIFICATION")
    print("=====================")

    found = False

    if hasattr(pe, "FileInfo") and pe.FileInfo:

        for group in pe.FileInfo:
            for item in group:

                if hasattr(item, "StringTable"):

                    for table in item.StringTable:

                        entries = table.entries

                        for key in [
                            b"FileVersion",
                            b"ProductVersion",
                            b"ProductName",
                            b"CompanyName"
                        ]:
                            print(key.decode(), ":", key in entries)

                            if all(k in entries for k in [
                                b"FileVersion",
                                b"ProductVersion",
                                b"ProductName",
                                b"CompanyName"
                            ]):
                                found = True

    print("\nAll required entries found:", found)
    print("VS_FIXEDFILEINFO exists:", bool(
        getattr(pe, "VS_FIXEDFILEINFO", None)
    ))

    pe.close()

except Exception as error:
    print("Error:", error)
