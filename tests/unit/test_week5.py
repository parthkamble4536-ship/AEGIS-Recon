"""
Week 5 tests — Containerization, Dockerfile, Docker Compose, and Security Controls.

Validates that container manifests meet production security standards:
- Multi-stage build
- Non-root user execution
- Healthcheck integration
- Volume persistence
- Secret exclusion in .dockerignore
"""

from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestDockerfileValidation:
    """Validates Dockerfile design and security controls."""

    @property
    def dockerfile_content(self) -> str:
        dockerfile_path = PROJECT_ROOT / "Dockerfile"
        assert dockerfile_path.exists(), "Dockerfile must exist at project root"
        return dockerfile_path.read_text(encoding="utf-8")

    def test_multi_stage_build(self):
        """Verifies multi-stage build to minimize attack surface and image size."""
        content = self.dockerfile_content
        assert "AS builder" in content, "Dockerfile must define a builder stage"
        assert "AS runner" in content, "Dockerfile must define a runner stage"

    def test_runs_as_non_root(self):
        """Container must switch to an unprivileged user (UID != 0)."""
        content = self.dockerfile_content
        assert "USER aegis" in content, "Dockerfile must switch to unprivileged user 'aegis'"
        assert "useradd" in content, "Dockerfile must create unprivileged user"

    def test_installs_nmap_and_curl(self):
        """Nmap is required for scanning, curl for health checks."""
        content = self.dockerfile_content
        assert "nmap" in content, "Dockerfile must install Nmap"
        assert "curl" in content, "Dockerfile must install curl"

    def test_healthcheck_directive_present(self):
        """Dockerfile must specify a healthcheck directive probing /api/health."""
        content = self.dockerfile_content
        assert "HEALTHCHECK" in content
        assert "/api/health" in content

    def test_exposes_port_8000(self):
        """Dockerfile must expose the default API server port."""
        content = self.dockerfile_content
        assert "EXPOSE 8000" in content


class TestDockerignoreValidation:
    """Validates that .dockerignore prevents leaking secrets or bloating image."""

    @property
    def dockerignore_lines(self) -> list[str]:
        path = PROJECT_ROOT / ".dockerignore"
        assert path.exists(), ".dockerignore must exist at project root"
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

    def test_ignores_environment_files(self):
        """Secrets from .env files must never be included in Docker build context."""
        lines = self.dockerignore_lines
        assert any(".env" in line for line in lines), ".dockerignore must exclude .env files"

    def test_ignores_git_metadata(self):
        lines = self.dockerignore_lines
        assert ".git" in lines

    def test_ignores_virtualenv(self):
        lines = self.dockerignore_lines
        assert any("venv" in line for line in lines)

    def test_ignores_tests_and_caches(self):
        lines = self.dockerignore_lines
        assert any("pytest" in line for line in lines)
        assert any("__pycache__" in line for line in lines)


class TestDockerComposeValidation:
    """Validates docker-compose.yml configuration."""

    @property
    def compose_config(self) -> dict:
        path = PROJECT_ROOT / "docker-compose.yml"
        assert path.exists(), "docker-compose.yml must exist at project root"
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_service_defined(self):
        config = self.compose_config
        assert "services" in config
        assert "aegis-recon" in config["services"]

    def test_port_mapping(self):
        service = self.compose_config["services"]["aegis-recon"]
        ports = service.get("ports", [])
        assert any("8000:8000" in str(p) for p in ports)

    def test_persistent_data_volume(self):
        """Ensures database data is preserved across container recreations."""
        service = self.compose_config["services"]["aegis-recon"]
        volumes = service.get("volumes", [])
        assert any("aegis-data:/app/data" in str(v) for v in volumes)
        assert "volumes" in self.compose_config
        assert "aegis-data" in self.compose_config["volumes"]

    def test_allowlist_mount_read_only(self):
        """Allows mounting external allowlist without modifying image."""
        service = self.compose_config["services"]["aegis-recon"]
        volumes = service.get("volumes", [])
        assert any("allowlist.yaml" in str(v) for v in volumes)

    def test_healthcheck_configured(self):
        service = self.compose_config["services"]["aegis-recon"]
        assert "healthcheck" in service
        test_cmd = service["healthcheck"].get("test", [])
        assert any("health" in str(t) for t in test_cmd)

