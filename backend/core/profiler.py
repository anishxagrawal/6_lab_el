import os
import json
from pathlib import Path
from typing import Any, Dict, Set

SKIP_DIRS: Set[str] = {
    "node_modules",
    "venv",
    ".git",
    ".next",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".idea",
    ".vscode",
}

LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".tf": "Terraform",
}


def build_repository_profile(repo_path: str) -> Dict[str, Any]:
    """
    Analyze the files and directories inside repo_path to determine
    the tech stack: languages, frameworks, APIs, infrastructure, and
    security elements present in the codebase.
    """
    repo_dir = Path(repo_path)
    if not repo_dir.exists():
        return {
            "languages": [],
            "frameworks": [],
            "infrastructure": [],
            "security_features": [],
            "apis": [],
        }

    detected_exts: Set[str] = set()
    frameworks: Set[str] = set()
    infrastructure: Set[str] = set()
    security_features: Set[str] = set()
    apis: Set[str] = set()

    # Search signatures in specific files
    package_json_paths = []
    python_reqs_paths = []

    for root, dirs, files in os.walk(repo_path):
        # Skip noisy/build directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        # Scan folder/file structures
        relative_root = os.path.relpath(root, repo_path)
        if relative_root == ".":
            relative_root = ""

        # Check path for GitHub Actions
        if ".github/workflows" in root.replace("\\", "/"):
            infrastructure.add("GitHub Actions")
            
        # Check path for Kubernetes configurations
        if "kubernetes" in root.replace("\\", "/").lower() or "k8s" in root.replace("\\", "/").lower():
            infrastructure.add("Kubernetes")

        for f in files:
            lower_name = f.lower()
            ext = Path(f).suffix.lower()

            if ext in LANGUAGE_EXTENSIONS:
                detected_exts.add(LANGUAGE_EXTENSIONS[ext])

            # Manifest collectors
            if lower_name == "package.json":
                package_json_paths.append(os.path.join(root, f))
            elif lower_name in ["requirements.txt", "pyproject.toml", "pipfile"]:
                python_reqs_paths.append(os.path.join(root, f))

            # Infrastructure detection
            if lower_name == "dockerfile":
                infrastructure.add("Docker")
            elif lower_name in ["docker-compose.yml", "docker-compose.yaml"]:
                infrastructure.add("Docker Compose")
            elif ext == ".tf":
                infrastructure.add("Terraform")
            elif lower_name in ["k8s.yaml", "k8s.yml"] or "kubernetes" in lower_name:
                infrastructure.add("Kubernetes")

            # API detection
            if ext == ".proto":
                apis.add("gRPC")
            elif ext == ".graphql" or lower_name.endswith(".schema.graphql"):
                apis.add("GraphQL")

    # Read JS/TS package.json files
    for pj_path in package_json_paths:
        try:
            with open(pj_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                deps = {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                }

                # Frameworks
                if "next" in deps:
                    frameworks.add("Next.js")
                if "react" in deps:
                    frameworks.add("React")
                if "express" in deps:
                    frameworks.add("Express")
                if "vue" in deps:
                    frameworks.add("Vue")
                if "@angular/core" in deps:
                    frameworks.add("Angular")

                # Security / APIs
                if "jsonwebtoken" in deps or "passport" in deps or "@clerk/nextjs" in deps or "@supabase/supabase-js" in deps:
                    security_features.add("Authentication / Session Management")
                if "cors" in deps:
                    security_features.add("CORS Configuration")
                if "express-rate-limit" in deps:
                    security_features.add("Rate Limiting")
                if "apollo-server" in deps or "graphql" in deps:
                    apis.add("GraphQL")
                if "socket.io" in deps or "ws" in deps:
                    apis.add("WebSockets")
        except Exception:
            pass

    # Read Python requirement manifests
    for py_path in python_reqs_paths:
        try:
            with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()

                # Frameworks
                if "django" in content:
                    frameworks.add("Django")
                if "fastapi" in content:
                    frameworks.add("FastAPI")
                if "flask" in content:
                    frameworks.add("Flask")

                # Security / APIs
                if "pyjwt" in content or "oauthlib" in content or "passlib" in content:
                    security_features.add("Authentication / Session Management")
                if "django-cors-headers" in content or "fastapi" in content:
                    # FastAPI has built-in CORS middleware
                    security_features.add("CORS Configuration")
                if "slowapi" in content:
                    security_features.add("Rate Limiting")
                if "strawberry-graphql" in content or "graphene" in content:
                    apis.add("GraphQL")
        except Exception:
            pass

    # Generic fallbacks
    if "Python" in detected_exts and not frameworks:
        # Check if manage.py is present
        if (repo_dir / "manage.py").exists():
            frameworks.add("Django")

    # If any web frameworks are present, label API context as REST by default
    web_frameworks = {"FastAPI", "Flask", "Django", "Express", "Next.js"}
    if frameworks.intersection(web_frameworks):
        apis.add("REST API")

    return {
        "languages": sorted(list(detected_exts)),
        "frameworks": sorted(list(frameworks)),
        "infrastructure": sorted(list(infrastructure)),
        "security_features": sorted(list(security_features)),
        "apis": sorted(list(apis)),
    }
