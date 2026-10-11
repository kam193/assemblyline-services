import yaml
from assemblyline.common import forge

SIGNATURE_DELIMITER = "\n#SIGNATURE-DELIMITER#\n\n"
SOURCE = "test-source"


def rule(id, pattern, *, severity="WARNING", message=None, languages=("python",), **extra):
    return {
        "id": id,
        "pattern": pattern,
        "message": message or f"Message of {id}",
        "severity": severity,
        "languages": list(languages),
        **extra,
    }


def write_rules(tmp_path, *rules, source=SOURCE):
    path = tmp_path / "rules" / source
    path.parent.mkdir(exist_ok=True)
    path.write_text(SIGNATURE_DELIMITER.join(yaml.safe_dump(r) for r in rules))
    return path


def default_meta(*rules, classification=None, status="DEPLOYED"):
    classification = classification or forge.get_classification().UNRESTRICTED
    return {r["id"]: {"classification": classification, "status": status} for r in rules}
