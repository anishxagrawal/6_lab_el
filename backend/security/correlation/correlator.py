from typing import Any, Dict, List
import re

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
    # 1. Group findings by (file_path, cwe_category) first
    groups_by_file_cwe: Dict[str, List[Dict[str, Any]]] = {}
    
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
        
        key = (file_path, cwe)
        if key not in groups_by_file_cwe:
            groups_by_file_cwe[key] = []
        groups_by_file_cwe[key].append(f)

    correlated_findings: List[Dict[str, Any]] = []

    # 2. Sub-cluster findings in each group based on line number tolerance (within 5 lines)
    for (file_path, cwe), group_findings in groups_by_file_cwe.items():
        sub_clusters: List[List[Dict[str, Any]]] = []
        for f in group_findings:
            added = False
            for cluster in sub_clusters:
                for member in cluster:
                    m_line = member.get("line_number") or 0
                    f_line = f.get("line_number") or 0
                    
                    # Merge if line numbers are within a tolerance of 5 lines
                    line_match = abs(m_line - f_line) <= 5
                    
                    # If one of them has line 0 (Trivy, history), check if rule/type matches
                    if m_line == 0 or f_line == 0:
                        m_type = (member.get("secret_type") or member.get("rule_name") or "").lower()
                        f_type = (f.get("secret_type") or f.get("rule_name") or "").lower()
                        line_match = (m_type in f_type) or (f_type in m_type) or (member.get("cwe") == f.get("cwe") and member.get("file_path") == f.get("file_path"))
                    
                    if line_match:
                        cluster.append(f)
                        added = True
                        break
                if added:
                    break
            if not added:
                sub_clusters.append([f])

        # 3. Process and merge each sub-cluster
        for cluster in sub_clusters:
            # Source type priority for primary record choosing
            source_priority = {"codeql": 4, "semgrep": 3, "trivy": 2, "pattern": 1, "entropy": 1, "history": 1}
            primary = max(cluster, key=lambda x: source_priority.get(x.get("source_type") or x.get("detection_method") or "secrets", 0))
            
            merged = dict(primary)
            
            # Map all scanners/engines present in this sub-cluster
            scanners = list(set(f.get("source_type") or f.get("detection_method") or "secrets" for f in cluster))
            merged["supporting_scanners"] = scanners
            
            # Engines metadata mapping
            engines = []
            for f in cluster:
                s_type = f.get("source_type") or f.get("detection_method") or "secrets"
                name = "Secret Detection"
                engine_type = "Pattern Matching"
                if s_type == "semgrep":
                    name = "Semgrep"
                    engine_type = "Pattern-based SAST"
                elif s_type == "codeql":
                    name = "CodeQL"
                    engine_type = "Semantic SAST"
                elif s_type == "trivy":
                    name = "Trivy"
                    engine_type = "Dependency Scanner"
                elif s_type == "history":
                    name = "Git History"
                    engine_type = "Historical Exposure"
                elif s_type == "entropy":
                    name = "Secret Detection"
                    engine_type = "Entropy Analysis"
                    
                rule_query = f.get("rule_id") or f.get("secret_type") or "Vulnerability"
                
                if not any(eng["name"] == name and eng["rule"] == rule_query for eng in engines):
                    engines.append({
                        "name": name,
                        "type": engine_type,
                        "rule": rule_query,
                        "query": rule_query,
                        "severity": (f.get("severity") or "MEDIUM").upper()
                    })
            merged["engines"] = engines
            
            # Severity Resolution: choose highest severity
            severity_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            highest_severity = None
            for f in cluster:
                curr_sev = str(f.get("severity") or "LOW").upper()
                if curr_sev in severity_priority:
                    if highest_severity is None or severity_priority[curr_sev] > severity_priority[highest_severity]:
                        highest_severity = curr_sev
            
            if highest_severity is not None:
                merged["severity"] = highest_severity.upper()
            else:
                merged["severity"] = primary.get("severity")
            
            # Accumulate code flows
            code_flow = []
            for f in cluster:
                if f.get("code_flow"):
                    code_flow.extend(f["code_flow"])
            merged["code_flow"] = code_flow
            
            # Deduplicate occurrences
            occs = []
            for f in cluster:
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
            
            unique_occs = []
            for o in occs:
                if not any(u["file_path"] == o["file_path"] and u["line_number"] == o["line_number"] for u in unique_occs):
                    unique_occs.append(o)
            merged["occurrences"] = unique_occs
            
            # Calculate line range string for descriptive output
            lines = [o.get("line_number") for o in unique_occs if o.get("line_number")]
            if lines:
                min_line, max_line = min(lines), max(lines)
                if min_line != max_line:
                    merged["line_range"] = f"{min_line}-{max_line}"
                else:
                    merged["line_range"] = str(min_line)
            else:
                merged["line_range"] = str(merged.get("line_number") or 0)
            
            # Confidence modifier agreement boost
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
