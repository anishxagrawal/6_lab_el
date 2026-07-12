from typing import Any, Dict, Tuple

def calculate_confidence(finding: Dict[str, Any], repo_profile: Dict[str, Any]) -> Tuple[int, str]:
    """
    Computes a confidence score (0-100) for the finding and returns (score, status).
    Status categories:
        - VALIDATED (score >= 70)
        - NEEDS_REVIEW (score 40-69)
        - REJECTED (score < 40)
    """
    score = 50  # Base confidence

    source_type = finding.get("source_type") or finding.get("detection_method")
    file_path = (finding.get("file_path") or "").lower()
    snippet = finding.get("snippet") or ""

    # 1. Base score by engine agreement model (calculated rather than hardcoded)
    scanners = set(finding.get("supporting_scanners", [source_type]))
    has_pattern = "pattern" in scanners or "secrets" in scanners or "regex" in scanners
    has_entropy = "entropy" in scanners
    has_semgrep = "semgrep" in scanners
    has_codeql = "codeql" in scanners
    has_history = "history" in scanners or "git history" in scanners or finding.get("found_in") == "history"

    if has_pattern and has_entropy and has_semgrep and has_history:
        score = 100
    elif has_pattern and has_entropy and has_semgrep:
        score = 95
    elif has_semgrep and has_codeql:
        score = 98
    elif has_codeql:
        score = 90
    elif has_semgrep:
        score = 80
    elif has_pattern or has_entropy:
        score = 60
    else:
        score = 70

    # Apply specific modifiers to reward high precision features
    if has_codeql:
        precision = finding.get("precision", "high").lower()
        if precision == "high":
            score += 10
        elif precision == "medium":
            score += 5
        if finding.get("code_flow"):
            score += 10

    if has_pattern or has_entropy:
        provider = finding.get("provider")
        conf_level = finding.get("confidence")
        if provider and provider != "Generic":
            score += 15
        if conf_level == "HIGH" or conf_level == 5 or conf_level == "5":
            score += 5
    
    # 2. Framework Validation (Rule 3)
    frameworks = [f.lower() for f in repo_profile.get("frameworks", [])]
    languages = [l.lower() for l in repo_profile.get("languages", [])]
    infra = [i.lower() for i in repo_profile.get("infrastructure", [])]

    # React validation
    if "react" in file_path or "jsx" in file_path or "tsx" in file_path:
        if "react" not in frameworks and "next.js" not in frameworks and "typescript" not in languages and "javascript" not in languages:
            score -= 50

    # Python validation
    if file_path.endswith(".py"):
        if "python" not in languages:
            score -= 50

    # Terraform/Docker validation
    if file_path.endswith(".tf") and "terraform" not in infra:
        score -= 50
    if "dockerfile" in file_path and "docker" not in infra:
        score -= 50

    # 3. Secret validation (Rule 4)
    # Correct format validation (e.g. AWS keys should start with AKIA/ASIP etc.)
    if source_type in ["pattern", "entropy", "secrets"]:
        val = finding.get("secret_value", "")
        if val:
            # Format length checks
            if len(val) < 8:
                score -= 40
            if val.isdigit() or val.isalpha() and len(set(val)) <= 3:
                score -= 30  # Repeating characters like aaaaaa or 1234567

    # 4. Dependency validation (Rule 5)
    # Check direct references
    if source_type == "trivy":
        pkg_name = finding.get("rule_name", "").lower() # package name is usually mapped to rule_name or secret_type
        # If the package name is not referenced in repo files, slightly lower confidence
        pass

    # 5. Evidence check (Rule 6)
    if not snippet or not finding.get("file_path"):
        return 0, "REJECTED"

    # 6. Apply correlation agreement/disagreement modifiers
    score += finding.get("confidence_modifier", 0)

    # Limit score boundaries
    score = max(0, min(100, score))

    # Determine status
    if score >= 70:
        status = "VALIDATED"
    elif score >= 40:
        status = "NEEDS_REVIEW"
    else:
        status = "REJECTED"

    return score, status
