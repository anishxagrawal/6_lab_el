from typing import Any, Dict, List

def correlate_scanner_findings(
    raw_findings: List[Dict[str, Any]], 
    repo_profile: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Merge findings from Semgrep, CodeQL, Secrets, and Trivy.
    Correlates matching CWEs in the same files/functions, boosts confidence 
    when scanners agree, and handles false-positive reduction if CodeQL is 
    available but disagrees.
    """
    correlated_findings: List[Dict[str, Any]] = []

    # Map raw findings to helper dicts for grouping
    # Group by key: (file_path, cwe_category)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    
    # We first process CodeQL to know if it ran and what it flagged
    has_codeql = any(f.get("source_type") == "codeql" for f in raw_findings)
    
    for f in raw_findings:
        file_path = f.get("file_path", "")
        # Normalise CWE
        cwe = f.get("cwe") or ""
        if not cwe:
            # Fallback CWE mapping
            sec_type = (f.get("secret_type") or "").lower()
            rule_id = (f.get("rule_id") or "").lower()
            if "sql" in rule_id or "sql" in sec_type:
                cwe = "CWE-89"
            elif "xss" in rule_id or "xss" in sec_type:
                cwe = "CWE-79"
            elif "secret" in sec_type or "key" in sec_type or "token" in sec_type:
                cwe = "CWE-798"
            elif "ssrf" in rule_id:
                cwe = "CWE-918"
            else:
                cwe = "CWE-200"

        f["cwe"] = cwe
        
        # Group key based on path + cwe
        key = f"{file_path}-{cwe}"
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    for key, group in groups.items():
        # Identify scanners present in this group
        scanners = list(set(f.get("source_type") or f.get("detection_method") or "secrets" for f in group))
        
        # Primary record is CodeQL if available, else first scanner
        primary = next((f for f in group if f.get("source_type") == "codeql"), group[0])
        
        # Merge supporting details
        merged = dict(primary)
        merged["supporting_scanners"] = scanners
        
        # Accumulate code flows
        code_flow = []
        for f in group:
            if f.get("code_flow"):
                code_flow.extend(f["code_flow"])
        merged["code_flow"] = code_flow
        
        # Deduplicate occurrences across matches
        occs = []
        for f in group:
            if f.get("occurrences"):
                occs.extend(f["occurrences"])
            else:
                occs.append({
                    "file_path": f.get("file_path"),
                    "line_number": int(f.get("line_number") or 0),
                    "snippet": f.get("snippet") or "",
                    "found_in": f.get("found_in") or "current",
                    "commit_hash": f.get("commit_hash")
                })
        
        # Deduplicate occs list
        unique_occs = []
        for o in occs:
            if not any(u["file_path"] == o["file_path"] and u["line_number"] == o["line_number"] for u in unique_occs):
                unique_occs.append(o)
        
        merged["occurrences"] = unique_occs

        # Confidence modifier (Phase 8):
        # Boost confidence when multiple scanners agree
        boost = 0
        if len(scanners) >= 2:
            boost += 25
            
        # CodeQL semantic data flow validation:
        # If Semgrep/Trivy reports an injection issue but CodeQL was executed (has_codeql is True)
        # and CodeQL did NOT flag any query path in this file (scanners contains Semgrep/Trivy but NOT CodeQL),
        # we lower confidence by 35 (Phase 7 False Positive heuristics).
        if has_codeql and "codeql" not in scanners and ("semgrep" in scanners or "trivy" in scanners):
            boost -= 35

        merged["confidence_modifier"] = boost
        correlated_findings.append(merged)

    return correlated_findings
