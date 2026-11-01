
import yara
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RULE_FILE = BASE_DIR / "utils" / "peid.yara"

# Compile original ClaMP PEiD rules
rules = yara.compile(filepath=str(RULE_FILE))


def detect_packer(file_path):
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("File not found")

    try:
        matches = rules.match(
            str(file_path),
            timeout=15
        )

        # Keep only packer names used in ClaMP dataset
        dataset_packers = {
            "AHPack01FEUERRADER",
            "ASPackv10803AlexeySolodovnikov",
            "ASPackv212AlexeySolodovnikov",
            "ASProtect13321RegisteredAlexeySolodovnikov",
            "Armadillov171",
            "Armadillov1xxv2xx",
            "AsCryptv01SToRM5",
            "BobSoftMiniDelphiBoBBobSoft",
            "CrunchPE",
            "D1S1Gv11betaD1N",
            "InstallShield2000",
            "InstallShieldCustom",
            "MacromediaWindowsFlashProjectorPlayerv50",
            "MacromediaWindowsFlashProjectorPlayerv60",
            "MicrosoftVisualCV80Debug",
            "MinGWGCC3x",
            "NETDLLMicrosoft",
            "NETexecutableMicrosoft",
            "PECompact2xxSlimLoaderBitSumTechnologies",
            "PECompactV2XBitsumTechnologies",
            "PECompactv2xx",
            "PEPaCKv10CCopyright1998byANAKiN",
            "PrivateexeProtector21522XSetiSoftTeam",
            "ProtectSharewareV11eCompservCMS",
            "PureBasic4xNeilHodgson",
            "Safe20",
            "StelthPE101BGCorp",
            "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
            "UPX293300LZMAMarkusOberhumerLaszloMolnarJohnReiser",
            "UPXProtectorv10x2",
            "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
            "UPXv20MarkusLaszloReiser",
            "Upackv039finalDwing",
            "VideoLanClient",
            "WinZip32bitSFXv8xmodule",
            "WiseInstallerStub",
            "XtremeProtectorv105",
            "nSpackV2xLiuXingPing",
            "tElock09910privatetE"
        }

        matched_names = sorted({
            match.rule
            for match in matches
            if match.rule in dataset_packers
        })

        if matched_names:
            return {
                "packer": 1,
                "packer_type": matched_names[0],
                "all_matches": matched_names
            }

        return {
            "packer": 0,
            "packer_type": "NoPacker",
            "all_matches": []
        }

    except yara.TimeoutError:
        raise RuntimeError("YARA scanning timed out")

    except yara.Error as error:
        raise RuntimeError(f"YARA scanning failed: {error}")
