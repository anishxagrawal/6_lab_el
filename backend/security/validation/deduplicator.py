from typing import Any, Dict, List

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapse identical or near-identical findings across files or lines.
    Groups findings by secret_hash + secret_type (rule).
    """
    collapsed: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        # Group by hash + type
        hash_val = f.get("secret_hash") or f.get("rule_id") or ""
        sec_type = f.get("secret_type") or f.get("rule_id") or "vulnerability"
        key = f"{hash_val}-{sec_type}"

        occ = {
            "file_path": f.get("file_path"),
            "line_number": int(f.get("line_number") or 0),
            "snippet": f.get("snippet") or "",
            "found_in": f.get("found_in") or "current",
            "commit_hash": f.get("commit_hash"),
        }

        if key not in collapsed:
            # First occurrence determines primary fields
            collapsed[key] = {
                **f,
                "occurrences": [occ]
            }
        else:
            # Check if this occurrence is already in the list
            existing_occs = collapsed[key]["occurrences"]
            if not any(o["file_path"] == occ["file_path"] and o["line_number"] == occ["line_number"] for o in existing_occs):
                existing_occs.append(occ)

    return list(collapsed.values())
