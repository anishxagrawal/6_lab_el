import tempfile
import shutil
import json
from pathlib import Path
from core.profiler import build_repository_profile


def test_build_repository_profile():
    # Set up temp workspace
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # Create directories
        (temp_dir / "src").mkdir()
        (temp_dir / "k8s").mkdir()
        
        # Write language files
        (temp_dir / "src" / "main.py").write_text("print('hello')", encoding="utf-8")
        (temp_dir / "src" / "component.tsx").write_text("// React TS component", encoding="utf-8")
        
        # Write requirements.txt
        reqs_content = "fastapi==0.100.0\nuvicorn\nslowapi\n"
        (temp_dir / "requirements.txt").write_text(reqs_content, encoding="utf-8")
        
        # Write package.json
        package_data = {
            "dependencies": {
                "react": "^18.2.0",
                "next": "^13.4.0",
                "jsonwebtoken": "^9.0.0"
            }
        }
        with open(temp_dir / "package.json", "w", encoding="utf-8") as f:
            json.dump(package_data, f)
            
        # Write infra configs
        (temp_dir / "Dockerfile").write_text("FROM python:3.11", encoding="utf-8")
        (temp_dir / "k8s" / "deployment.yaml").write_text("apiVersion: apps/v1", encoding="utf-8")
        (temp_dir / "main.tf").write_text("resource \"aws_s3_bucket\" \"b\" {}", encoding="utf-8")

        # Run profiling
        profile = build_repository_profile(str(temp_dir))

        # Asserts
        assert "Python" in profile["languages"]
        assert "TypeScript (React)" in profile["languages"]
        
        assert "FastAPI" in profile["frameworks"]
        assert "Next.js" in profile["frameworks"]
        assert "React" in profile["frameworks"]
        
        assert "Docker" in profile["infrastructure"]
        assert "Terraform" in profile["infrastructure"]
        assert "Kubernetes" in profile["infrastructure"]
        
        assert "Authentication / Session Management" in profile["security_features"]
        assert "CORS Configuration" in profile["security_features"]
        assert "Rate Limiting" in profile["security_features"]
        
        assert "REST API" in profile["apis"]

    finally:
        shutil.rmtree(temp_dir)
