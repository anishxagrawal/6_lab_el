from __future__ import annotations

import hashlib
import hmac
import os
import re
import smtplib
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
import math

from ai.reasoning import build_reasoning

from alerts.email_alerts import (
    mail_alerts_enabled,
    send_critical_mail,
)

from core.crypto import (
    build_cipher,
    hash_secret,
    hmac_sha256_hex,
)

from core.exposure import (
    calculate_exposure_score,
    get_first_commit_date,
    hydrate_missing_exposure_fields,
)

from security.github_clone import (
    clone_repository,
    cleanup_repository,
)

from security.secret_scanner import (
    scan_file,
    should_skip_file,
)

from security.semgrep.service import SemgrepService

import httpx
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq
from pydantic import BaseModel
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

from security.semgrep.service import SemgrepService

import tempfile
import subprocess
import shutil

BACKEND_ROOT = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_ROOT.parent
for env_path in (BACKEND_ROOT / ".env", REPO_ROOT / ".env"):
    if env_path.exists():
        load_dotenv(env_path, override=False)


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "").strip()
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "").strip()

if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY is required in .env")

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = "".join(os.environ.get("SMTP_PASSWORD", "").split())
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "15"))
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "").strip()
ALERT_EMAIL_TO = [
    recipient.strip()
    for recipient in os.environ.get("ALERT_EMAIL_TO", "").split(",")
    if recipient.strip()
]
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


cipher = build_cipher(ENCRYPTION_KEY)

def debug_log(*args, **kwargs):
    """Print with automatic flush for logging"""
    print(*args, **kwargs, file=sys.stderr, flush=True)
    sys.stdout.flush()


app = FastAPI(title="DarkShield Backend", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


PATTERNS: dict[str, tuple[str, str]] = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "HIGH"),
    "AWS Secret Key": (r"(?i)aws.{0,20}secret.{0,20}[\'\"][0-9a-zA-Z/+=]{40}[\'\"]", "CRITICAL"),
    "OpenAI Key": (r"sk-[a-zA-Z0-9]{32,}", "HIGH"),
    "Anthropic Key": (r"sk-ant-[a-zA-Z0-9\-]{90,}", "HIGH"),
    "Groq Key": (r"gsk_[a-zA-Z0-9]{50,}", "HIGH"),
    "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "HIGH"),
    "Stripe Secret": (r"sk_live_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Slack Token": (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "MEDIUM"),
    "Private Key": (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    "Generic Password": (r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?", "MEDIUM"),
    "Generic Secret": (r"(?i)(secret|api_key|api_secret|access_token)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?", "MEDIUM"),
}

SKIP_EXT = {
    ".png",
    ".jpg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".ttf",
    ".zip",
    ".pdf",
    ".lock",
    ".min.js",
    ".map",
    ".exe",
    ".bin",
}


class ScanRequest(BaseModel):
    repo_id: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _safe_repo_lookup(client: Client, repo_id: str) -> dict[str, Any]:
    response = client.table("repos").select("*").eq("id", repo_id).limit(1).execute()
    rows = getattr(response, "data", []) or []
    if not rows:
        raise HTTPException(status_code=404, detail="Repo not found")
    return rows[0]


def _parse_status(status: str | None) -> str:
    value = str(status or "").upper().strip()
    if value in {"PENDING", "SCANNING", "DONE", "ERROR"}:
        return value.lower()
    return "pending"


def _supabase_for_request(request: Request | None) -> Client:
    if request is not None:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", maxsplit=1)[1].strip()
            if token:
                return create_client(
                    SUPABASE_URL,
                    SUPABASE_KEY,
                    options=SyncClientOptions(
                        headers={"Authorization": f"Bearer {token}"},
                        auto_refresh_token=False,
                        persist_session=False,
                    ),
                )

    return supabase

def _severity_rank(severity: str) -> int:
    mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return mapping.get(severity.upper(), 1)

def _distinct_repo_count_for_hash(client: Client, secret_hash: str) -> int:
    response = client.table("findings").select("repo_id").eq("secret_hash", secret_hash).execute()
    rows = getattr(response, "data", []) or []
    return len({str(row.get("repo_id") or "") for row in rows if row.get("repo_id")})


def _aggregate_clusters(client: Client) -> list[dict[str, Any]]:
    response = client.table("findings").select("secret_hash,secret_type,severity,created_at,repo_id").execute()
    rows = getattr(response, "data", []) or []
    grouped: dict[str, dict[str, Any]] = {}

    for row in rows:
        secret_hash = str(row.get("secret_hash") or "").strip()
        if not secret_hash:
            continue

        group = grouped.setdefault(
            secret_hash,
            {
                "id": secret_hash,
                "secret_hash": secret_hash,
                "secret_type": row.get("secret_type") or "Unknown",
                "severity": row.get("severity") or "LOW",
                "repo_ids": set(),
                "created_at": row.get("created_at"),
            },
        )
        if row.get("repo_id"):
            group["repo_ids"].add(str(row["repo_id"]))
        if _severity_rank(str(row.get("severity") or "LOW")) > _severity_rank(str(group["severity"])):
            group["severity"] = row.get("severity") or group["severity"]
        if row.get("created_at") and (not group["created_at"] or str(row["created_at"]) < str(group["created_at"])):
            group["created_at"] = row.get("created_at")

    result: list[dict[str, Any]] = []
    for group in grouped.values():
        repo_ids = group.pop("repo_ids")
        repo_count = len(repo_ids)
        if repo_count < 2:
            continue
        group["repo_count"] = repo_count
        result.append(group)

    result.sort(key=lambda item: (item.get("repo_count", 0), item.get("created_at") or ""), reverse=True)
    return result

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_repo(req: ScanRequest, request: Request) -> dict[str, Any]:
    print(f"\nSCAN: Starting scan for repo ID: {req.repo_id}")
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, req.repo_id)
    owner = str(repo.get("owner") or "").strip()
    name = str(repo.get("name") or "").strip()
    github_url = str(repo.get("github_url") or "").strip()

    print(f"SCAN: {owner}/{name}")
    client.table("repos").update({"status": "scanning"}).eq("id", req.repo_id).execute()

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    semgrep_service = SemgrepService()

    cloned_repo_path = None
    semgrep_result = None

    try:
        cloned_repo_path = clone_repository(
            github_url
        )

        print(
            f"SEMGREP: Repository cloned to {cloned_repo_path}"
        )

        semgrep_result = (
            semgrep_service.analyze_and_convert(
                repo_id=req.repo_id,
                repo_path=cloned_repo_path,
            )
        )

        print(
            f"SEMGREP: Found {len(semgrep_result['records'])} findings"
        )

        findings_raw: list[dict[str, Any]] = []   

    except Exception as exc:

        print(
            f"WARNING: Semgrep scan failed: {exc}"
        )

        semgrep_result = {
            "records": [],
            "categories": [],
            "owasp_context": "",
            "total_findings": 0,
        }    

    try:
        async with httpx.AsyncClient(timeout=30, headers=headers) as http_client:
            tree_resp = await http_client.get(
                f"https://api.github.com/repos/{owner}/{name}/git/trees/HEAD?recursive=1"
            )
            if tree_resp.status_code != 200:
                print(f"ERROR: Failed to fetch repo tree: {tree_resp.status_code}")
                client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
                raise HTTPException(status_code=400, detail="Could not fetch repo. Is it public?")

            tree = tree_resp.json().get("tree", [])
            files = [
                item
                for item in tree
                if item.get("type") == "blob" and not should_skip_file(str(item.get("path") or ""), item.get("size"))
            ]

            print(f"SCAN: Scanning {len(files)} files...")
            for file_item in files[:200]:
                await scan_file(
                    client=http_client,
                    owner=owner,
                    name=name,
                    file_path=str(file_item.get("path") or ""),
                    repo_id=req.repo_id,
                    findings=findings_raw,
                    get_first_commit_date=get_first_commit_date,
                    hash_secret=hash_secret,
                    encrypt_snippet=cipher.encrypt,
                    calculate_exposure_score=calculate_exposure_score,
                    hmac_secret_key=HMAC_SECRET_KEY
                )
    except HTTPException:
        raise
    except Exception as exc:
        print(f"ERROR: Scan failed: {exc}")
        client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
        raise HTTPException(status_code=500, detail=f"Repository scan failed: {type(exc).__name__}: {exc}") from exc

    seen: set[tuple[str, str, int]] = set()
    unique_findings: list[dict[str, Any]] = []
    for finding in findings_raw:
        key = (finding["secret_hash"], finding["file_path"], int(finding["line_number"]))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    print(f"OK: Found {len(unique_findings)} unique secrets")

    semgrep_findings = (
        semgrep_result["records"]
    )

    print(
        f"SEMGREP: {len(semgrep_findings)} findings"
    )

    all_findings = (
        unique_findings
        + semgrep_findings
    )

    for finding in unique_findings:
        finding["cluster_id"] = None

    if unique_findings:
        print("DB: Saving findings to database...")
        client.table("findings").upsert(
            all_findings,
            on_conflict="repo_id,file_path,line_number,secret_hash",
        ).execute()
        print("OK: Findings saved")

    findings_for_reasoning: list[dict[str, Any]] = []
    for finding in unique_findings:
        finding["cluster_repo_count"] = _distinct_repo_count_for_hash(client, finding["secret_hash"])
        findings_for_reasoning.append(finding)

    print("AI: Generating AI reasoning...")
    ai_reasoning = build_reasoning(owner, name, findings_for_reasoning, groq_client)
    critical_findings = [finding for finding in unique_findings if str(finding.get("severity") or "").upper() == "CRITICAL"]
    print(f"ALERT: Critical findings: {len(critical_findings)}")
    
    mail_sent, mail_error = send_critical_mail(
                                client=client,
                                repo_id=req.repo_id,
                                owner=owner,
                                name=name,
                                repo_url=github_url,
                                critical_findings=critical_findings,
                                ai_reasoning=ai_reasoning,
                                total_count=len(all_findings),
                                smtp_host=SMTP_HOST,
                                smtp_port=SMTP_PORT,
                                smtp_user=SMTP_USER,
                                smtp_password=SMTP_PASSWORD,
                                smtp_use_ssl=SMTP_USE_SSL,
                                smtp_use_tls=SMTP_USE_TLS,
                                smtp_timeout=SMTP_TIMEOUT,
                                alert_email_from=ALERT_EMAIL_FROM,
                                alert_email_to=ALERT_EMAIL_TO,
                                hmac_sha256_hex=hmac_sha256_hex,
                                debug_log=debug_log,
                            )

    try:
        client.table("repos").update(
            {
                "status": "done",
                "last_scanned_at": _now_iso(),
                "finding_count": len(all_findings),
                "ai_reasoning": ai_reasoning,
            }
        ).eq("id", req.repo_id).execute()
    except Exception as exc:
        print(f"WARNING: Failed to finalize repo scan status: {exc}")

    print(f"OK: Scan complete for {owner}/{name}")

    if cloned_repo_path:

        try:
            shutil.rmtree(
                cloned_repo_path,
                ignore_errors=True,
            )

        except Exception:
            pass

    return {
        "repo_id": req.repo_id,
        "github_url": github_url,
        "total": len(all_findings),
        "ai_reasoning": ai_reasoning,
        "critical_alerts_enabled": mail_alerts_enabled(
            SMTP_HOST,
            SMTP_USER,
            SMTP_PASSWORD,
            ALERT_EMAIL_TO,
        ),
        "critical_alert_email_sent": mail_sent,
        "critical_alert_error": mail_error,
        "critical_findings": len(critical_findings),
    }


@app.delete("/repos/{repo_id}")
async def delete_repo(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    client.table("repos").delete().eq("id", repo_id).execute()
    return {
        "deleted": True,
        "repo_id": repo_id,
        "github_url": repo.get("github_url"),
        "owner": repo.get("owner"),
        "name": repo.get("name"),
    }


@app.get("/findings/{repo_id}")
async def get_findings(repo_id: str, request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    response = (
        client.table("findings")
        .select("*")
        .eq("repo_id", repo_id)
        .order("created_at", desc=True)
        .execute()
    )
    findings = getattr(response, "data", []) or []
    
    # Decrypt snippets on retrieval
    for finding in findings:
        if finding.get("snippet_enc"):
            finding["snippet"] = cipher.decrypt(finding["snippet_enc"])
        # Include exposure duration and score in response for older rows too.
        if finding.get("exposure_days") is None and finding.get("first_commit_date"):
            first_commit = datetime.fromisoformat(finding["first_commit_date"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            exposure_days = max(0, (now - first_commit).days)
            finding["exposure_days"] = exposure_days
            finding["exposure_score"] = calculate_exposure_score(
                finding.get("severity", "LOW"),
                exposure_days,
            )
    findings = await hydrate_missing_exposure_fields(client, str(repo.get("owner") or ""), str(repo.get("name") or ""), findings)

    return findings


@app.get("/clusters")
async def get_clusters(request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    return _aggregate_clusters(client)
