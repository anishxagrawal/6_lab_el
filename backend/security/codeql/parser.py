import json
from typing import Any, Dict, List
from .models import CodeQLFinding

def map_sarif_severity(result: Dict[str, Any], rule_meta: Dict[str, Any]) -> str:
    """
    Map SARIF severity levels / security-severity scores to standard levels:
    CRITICAL, HIGH, MEDIUM, LOW.
    """
    # Try security-severity score (0.0 - 10.0)
    properties = rule_meta.get("properties", {})
    sec_sev = properties.get("security-severity")
    if sec_sev is not None:
        try:
            score = float(sec_sev)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
        except (ValueError, TypeError):
            pass

    # Fallback to level
    level = result.get("level", "warning")
    if level == "error":
        return "CRITICAL"
    if level == "warning":
        return "HIGH"
    if level == "note":
        return "MEDIUM"
    return "LOW"

def extract_cwe_from_tags(properties: Dict[str, Any]) -> str:
    """Extract CWE reference from tags list (e.g. ['external/cwe/cwe-89'])."""
    tags = properties.get("tags", [])
    for tag in tags:
        if "cwe-" in tag.lower():
            # Extract CWE ID (e.g. CWE-89)
            parts = tag.lower().split("/")
            cwe_part = parts[-1]
            return cwe_part.upper()
    return "CWE-200"

def parse_codeql_sarif(sarif_path: str) -> List[CodeQLFinding]:
    """Parse SARIF file to extract CodeQLFindings with call chains."""
    findings = []
    
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"CODEQL PARSER ERROR: Failed to read SARIF file {sarif_path}: {e}")
        return findings

    runs = data.get("runs", [])
    if not runs:
        return findings
    
    run = runs[0]
    results = run.get("results", [])
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    
    # Build map of rules metadata
    rules_map = {rule.get("id"): rule for rule in rules if rule.get("id")}
    
    for res in results:
        rule_id = res.get("ruleId")
        rule_meta = rules_map.get(rule_id, {})
        
        severity = map_sarif_severity(res, rule_meta)
        cwe = extract_cwe_from_tags(rule_meta.get("properties", {}))
        
        # Extract locations
        locations = res.get("locations", [])
        if not locations:
            continue
        
        phys_loc = locations[0].get("physicalLocation", {})
        file_path = phys_loc.get("artifactLocation", {}).get("uri", "")
        line_number = phys_loc.get("region", {}).get("startLine", 0)
        
        message = res.get("message", {}).get("text", "No message provided.")
        title = rule_meta.get("shortDescription", {}).get("text") or rule_id or "CodeQL Finding"
        
        # Parse data flows / call chains
        code_flow = []
        code_flows = res.get("codeFlows", [])
        if code_flows:
            thread_flows = code_flows[0].get("threadFlows", [])
            if thread_flows:
                loc_steps = thread_flows[0].get("locations", [])
                for i, step in enumerate(loc_steps):
                    step_loc = step.get("location", {})
                    step_phys = step_loc.get("physicalLocation", {})
                    step_file = step_phys.get("artifactLocation", {}).get("uri", "")
                    step_line = step_phys.get("region", {}).get("startLine", 0)
                    step_msg = step_loc.get("message", {}).get("text", "")
                    
                    label = f"Step {i+1}: {step_msg}" if step_msg else f"Step {i+1}"
                    if i == 0:
                        label = f"Source: {step_msg}" if step_msg else "Source input"
                    elif i == len(loc_steps) - 1:
                        label = f"Sink: {step_msg}" if step_msg else "Sink execution"
                        
                    code_flow.append({
                        "file": step_file,
                        "line": step_line,
                        "label": label
                    })

        finding = CodeQLFinding(
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            title=title,
            severity=severity,
            message=message,
            cwe=cwe,
            precision=rule_meta.get("properties", {}).get("precision", "high"),
            code_flow=code_flow,
            owasp_category=None,
            code_snippet=None
        )
        findings.append(finding)
        
    return findings
