"""Builders for TagScan rule YAML and the updater-produced signatures_meta."""

import yaml


def rule(
    name,
    pattern,
    tag,
    *,
    id=None,
    heuristic=None,
    exclude_files=None,
    not_patterns=None,
    meta=None,
):
    doc = {"id": id or f"test.{name}", "name": name, "pattern": pattern, "tag": tag}
    if heuristic is not None:
        doc["heuristic"] = heuristic
    if exclude_files is not None:
        doc["exclude_files"] = exclude_files
    if not_patterns is not None:
        doc["not"] = not_patterns
    if meta is not None:
        doc["meta"] = meta
    return doc


def write_rules(tmp_path, *rules, filename="rules.yml"):
    path = tmp_path / filename
    path.write_text(yaml.safe_dump_all(rules))
    return path


def default_meta(*rules, source="test", status="DEPLOYED"):
    """signatures_meta entries the updater would have produced for these rules."""
    return {
        r["id"]: {
            "source": source,
            "name": r["name"],
            "signature_id": r["id"],
            "status": status,
        }
        for r in rules
    }
