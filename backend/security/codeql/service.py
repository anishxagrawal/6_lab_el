import os
import shutil
import tempfile
from typing import Any, Dict, List
from .constants import LANGUAGE_MAP
from .models import CodeQLAnalysisResult, CodeQLFinding
from .runner import check_codeql_available, run_codeql_db_create, run_codeql_analyze
from .parser import parse_codeql_sarif
from .converters import codeql_findings_to_records

class CodeQLService:
    """
    Orchestrator service for GitHub CodeQL dynamic analyses.
    """
    
    def analyze_repository(self, repo_path: str, repo_profile: Dict[str, Any]) -> CodeQLAnalysisResult:
        """
        Create temporary databases, run analyses for matching languages,
        parse results, and clean up workspace.
        """
        result = CodeQLAnalysisResult()
        
        if not check_codeql_available():
            print("CODEQL SERVICE: CodeQL CLI is not available in system path. Skipping CodeQL analysis.")
            return result

        languages = [l.lower() for l in repo_profile.get("languages", [])]
        matched_configs = []
        for lang in languages:
            if lang in LANGUAGE_MAP:
                matched_configs.append(LANGUAGE_MAP[lang])

        if not matched_configs:
            print("CODEQL SERVICE: No matching query packs found for languages: ", languages)
            return result

        tmp_dir = tempfile.mkdtemp(prefix="codeql_")
        try:
            for idx, config in enumerate(matched_configs):
                lang_key = config["codeql_lang"]
                pack = config["pack"]
                
                db_path = os.path.join(tmp_dir, f"db_{lang_key}_{idx}")
                sarif_path = os.path.join(tmp_dir, f"results_{lang_key}_{idx}.sarif")
                
                try:
                    # Database create
                    run_codeql_db_create(repo_path, db_path, lang_key)
                    # Database analyze
                    run_codeql_analyze(db_path, pack, sarif_path)
                    
                    # Parse findings
                    parsed_findings = parse_codeql_sarif(sarif_path)
                    result.findings.extend(parsed_findings)
                except Exception as e:
                    print(f"CODEQL SERVICE WARNING: Scan failed for language {lang_key}: {e}")
                    # Phase 17: Optional scanner: continue with next language
                    continue
                    
            # Compute stats
            result.total_findings = len(result.findings)
            for f in result.findings:
                sev = f.severity.upper()
                if sev == "CRITICAL":
                    result.critical_count += 1
                elif sev == "HIGH":
                    result.high_count += 1
                elif sev == "MEDIUM":
                    result.medium_count += 1
                else:
                    result.low_count += 1
                    
        finally:
            # Cleanup temporary files and databases (Phase 3)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            
        return result

    def analyze_and_convert(self, repo_id: str, repo_path: str, repo_profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run analyze_repository and convert output to standard dictionary record list.
        """
        analysis = self.analyze_repository(repo_path, repo_profile)
        records = codeql_findings_to_records(repo_id, analysis.findings)
        
        return {
            "records": records,
            "total_findings": analysis.total_findings,
            "critical_count": analysis.critical_count,
            "high_count": analysis.high_count,
            "medium_count": analysis.medium_count,
            "low_count": analysis.low_count
        }
