"""
GitHub repository scanner — language detection + static code vulnerability analysis.

Uses the GitHub REST API (optional GITHUB_TOKEN for higher rate limits).
"""

import base64
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx

GITHUB_API = "https://api.github.com"

SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rb",
    ".php",
    ".java",
    ".cs",
    ".rs",
    ".kt",
    ".swift",
    ".yaml",
    ".yml",
    ".json",
    ".sql",
    ".sh",
    ".bash",
    ".env",
    ".toml",
    ".cfg",
    ".ini",
    ".tf",
    ".hcl",
    ".tfvars",
}

PRIORITY_EXTENSIONS = {
    ".tf": 0,
    ".hcl": 0,
    ".tfvars": 1,
    ".py": 2,
    ".go": 2,
    ".js": 3,
    ".ts": 3,
}

SKIP_PATH_PARTS = {
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "coverage",
    ".next",
    "target",
    "tests",
    "__tests__",
    "spec",
}

MAX_FILES = 60
MAX_FILE_BYTES = 100_000

# (regex, owasp, name, severity, recommendation)
CODE_PATTERNS: list[tuple[str, str, str, str, str]] = [
    (
        r'(?i)(api[_-]?key|secret|password|token|auth)\s*=\s*["\'][^"\']{8,}["\']',
        "OWASP-A02",
        "Hardcoded Secret",
        "CRITICAL",
        "Move secrets to environment variables or a secrets manager",
    ),
    (
        r"(?i)(aws_access_key_id|aws_secret_access_key|sk-or-|sk_live_|ghp_[a-zA-Z0-9]{20,})",
        "OWASP-A02",
        "Exposed Credential Pattern",
        "CRITICAL",
        "Rotate the credential and remove it from source control",
    ),
    (
        r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.+\s*(%s|\+|\|\||\.format\(|f[\"'])",
        "OWASP-A03",
        "SQL Injection Risk",
        "HIGH",
        "Use parameterized queries or an ORM",
    ),
    (
        r"\beval\s*\(",
        "OWASP-A03",
        "Use of eval()",
        "HIGH",
        "Avoid eval; use safe parsing alternatives",
    ),
    (
        r"\bexec\s*\(",
        "OWASP-A03",
        "Use of exec()",
        "HIGH",
        "Remove dynamic code execution",
    ),
    (
        r"pickle\.loads\s*\(",
        "OWASP-A08",
        "Unsafe Deserialization",
        "HIGH",
        "Do not deserialize untrusted pickle data",
    ),
    (
        r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True",
        "OWASP-A03",
        "Shell Injection Risk",
        "HIGH",
        "Use shell=False and pass argument lists",
    ),
    (
        r"yaml\.load\s*\([^)]*\)",
        "OWASP-A08",
        "Unsafe YAML Load",
        "MEDIUM",
        "Use yaml.safe_load instead of yaml.load",
    ),
    (
        r"(?i)debug\s*=\s*True",
        "OWASP-A05",
        "Debug Mode Enabled",
        "MEDIUM",
        "Disable debug in production deployments",
    ),
    (
        r"(?i)verify\s*=\s*False",
        "OWASP-A02",
        "TLS Verification Disabled",
        "HIGH",
        "Enable certificate verification for HTTPS requests",
    ),
    (
        r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*",
        "OWASP-A05",
        "Permissive CORS",
        "MEDIUM",
        "Restrict CORS to trusted origins",
    ),
    (
        r"(?i)(md5|sha1)\s*\([^)]*password",
        "OWASP-A02",
        "Weak Password Hashing",
        "HIGH",
        "Use bcrypt, scrypt, or Argon2 for password hashing",
    ),
    (
        r"innerHTML\s*=",
        "OWASP-A03",
        "DOM XSS Risk",
        "MEDIUM",
        "Use textContent or sanitize HTML before insertion",
    ),
    (
        r"dangerouslySetInnerHTML",
        "OWASP-A03",
        "React XSS Risk",
        "MEDIUM",
        "Sanitize content before using dangerouslySetInnerHTML",
    ),
    (
        r"http://(?!localhost|127\.0\.0\.1)",
        "OWASP-A02",
        "Insecure HTTP URL",
        "LOW",
        "Use HTTPS for external communications",
    ),
]

# Terraform / HCL security patterns
TERRAFORM_PATTERNS: list[tuple[str, str, str, str, str]] = [
    (
        r"0\.0\.0\.0/0",
        "OWASP-A01",
        "Overly Permissive Network (0.0.0.0/0)",
        "CRITICAL",
        "Restrict security group rules to specific CIDR ranges, not the entire internet",
    ),
    (
        r'(?i)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "OWASP-A01",
        "Open Ingress CIDR (0.0.0.0/0)",
        "CRITICAL",
        "Replace 0.0.0.0/0 with least-privilege CIDR blocks",
    ),
    (
        r'(?i)acl\s*=\s*"public-read"',
        "OWASP-A01",
        "Public S3 ACL",
        "CRITICAL",
        "Use private buckets with IAM policies instead of public ACLs",
    ),
    (
        r"(?i)block_public_acls\s*=\s*false",
        "OWASP-A01",
        "S3 Public ACLs Allowed",
        "HIGH",
        "Set block_public_acls = true on S3 bucket resources",
    ),
    (
        r"(?i)ignore_public_acls\s*=\s*false",
        "OWASP-A01",
        "S3 Ignores Public ACLs Disabled",
        "HIGH",
        "Set ignore_public_acls = true to block public ACL usage",
    ),
    (
        r"(?i)(encrypt\s*=\s*false|storage_encrypted\s*=\s*false|encrypted\s*=\s*false)",
        "OWASP-A02",
        "Encryption Disabled",
        "HIGH",
        "Enable encryption at rest for storage and database resources",
    ),
    (
        r'action\s*=\s*"\*"',
        "OWASP-A01",
        "Wildcard IAM Action",
        "HIGH",
        "Scope IAM actions to the minimum permissions required",
    ),
    (
        r'resource\s*=\s*"\*"',
        "OWASP-A01",
        "Wildcard IAM Resource",
        "HIGH",
        "Restrict IAM resources to specific ARNs instead of *",
    ),
    (
        r"(?i)assign_public_ip\s*=\s*true",
        "OWASP-A05",
        "Public IP Assignment",
        "MEDIUM",
        "Avoid public IPs unless required; use private subnets and NAT",
    ),
    (
        r"(?i)mapPublicIpOnLaunch\s*=\s*true",
        "OWASP-A05",
        "Subnet Auto-Assigns Public IP",
        "MEDIUM",
        "Disable mapPublicIpOnLaunch for private subnets",
    ),
    (
        r'(?i)(password|secret|token|api_key)\s*=\s*"[^$"{][^"]{4,}"',
        "OWASP-A02",
        "Hardcoded Secret in Terraform",
        "CRITICAL",
        "Use variables, AWS Secrets Manager, or SSM Parameter Store",
    ),
    (
        r"(?i)protocol\s*=\s*\"-1\"",
        "OWASP-A01",
        "All Protocols Allowed in Security Group",
        "HIGH",
        "Restrict to specific protocols (tcp/udp) and ports",
    ),
]


def _should_skip_scan_path(path: str) -> bool:
    """Skip test fixtures and other non-production paths."""
    basename = os.path.basename(path)
    if basename.startswith("test_") and basename.endswith(".py"):
        return True
    if basename.endswith("_test.py") or basename.endswith("_test.ts"):
        return True
    if basename.endswith(".test.ts") or basename.endswith(".test.tsx"):
        return True
    if basename.endswith(".spec.ts") or basename.endswith(".spec.tsx"):
        return True
    return False


def _is_scanner_meta_line(line: str, matched_name: str) -> bool:
    """Ignore matches inside this file's own pattern/rule definitions."""
    stripped = line.strip()
    if f'"{matched_name}"' in stripped or f"'{matched_name}'" in stripped:
        return True
    if re.match(r'^\s*"[^"]*",?\s*$', stripped) or re.match(r"^\s*'[^']*',?\s*$", stripped):
        return True
    if "OWASP-A" in stripped and ('"' in stripped or "'" in stripped):
        return True
    if re.match(r'^\s*r["\']', stripped) and (
        "(?i)" in stripped or "\\" in stripped or "|" in stripped
    ):
        return True
    if re.match(r'^\s*r["\'][^"\']*["\'],?\s*$', stripped):
        return True
    return False


def parse_github_url(repo: str) -> tuple[str, str]:
    """Return (owner, repo_name) from URL or owner/repo string."""
    repo = repo.strip().rstrip("/")
    if repo.startswith("http"):
        parsed = urlparse(repo)
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) < 2:
            raise ValueError("Invalid GitHub URL — expected github.com/owner/repo")
        return parts[0], parts[1].replace(".git", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        return owner, name.replace(".git", "")
    raise ValueError("Invalid repo — use owner/repo or full GitHub URL")


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(client: httpx.Client, path: str) -> dict | list:
    resp = client.get(f"{GITHUB_API}{path}", headers=_headers(), timeout=20)
    resp.raise_for_status()
    return resp.json()


def fetch_repo_languages(client: httpx.Client, owner: str, repo: str) -> dict[str, float]:
    """Return language -> percentage of repo bytes."""
    data = _get(client, f"/repos/{owner}/{repo}/languages")
    if not data:
        return {}
    total = sum(data.values())
    return {lang: round(bytes_ / total * 100, 1) for lang, bytes_ in data.items()}


def fetch_default_branch(client: httpx.Client, owner: str, repo: str) -> str:
    meta = _get(client, f"/repos/{owner}/{repo}")
    return meta.get("default_branch", "main")


def list_scannable_files(
    client: httpx.Client,
    owner: str,
    repo: str,
    branch: str,
    languages: dict[str, float] | None = None,
) -> list[str]:
    tree = _get(client, f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    candidates: list[str] = []
    langs = languages or {}
    hcl_repo = "HCL" in langs and langs.get("HCL", 0) >= 10

    for item in tree.get("tree", []):
        if item.get("type") != "blob":
            continue
        path = item["path"]
        if any(part in SKIP_PATH_PARTS for part in path.split("/")):
            continue
        if _should_skip_scan_path(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext not in SCANNABLE_EXTENSIONS:
            continue
        if item.get("size", 0) > MAX_FILE_BYTES:
            continue
        candidates.append(path)

    def sort_key(path: str) -> tuple[int, str]:
        ext = os.path.splitext(path)[1].lower()
        if hcl_repo and ext in (".tf", ".hcl", ".tfvars"):
            return (0, path)
        priority = PRIORITY_EXTENSIONS.get(ext, 4)
        return (priority, path)

    candidates.sort(key=sort_key)
    return candidates[:MAX_FILES]


def fetch_file_content(client: httpx.Client, owner: str, repo: str, path: str) -> str:
    data = _get(client, f"/repos/{owner}/{repo}/contents/{path}")
    if isinstance(data, list):
        return ""
    content = data.get("content", "")
    if data.get("encoding") == "base64" and content:
        return base64.b64decode(content).decode("utf-8", errors="ignore")
    return content


def scan_source_code(content: str, path: str, language: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()
    ext = os.path.splitext(path)[1].lower()
    patterns = list(CODE_PATTERNS)
    if ext in (".tf", ".hcl", ".tfvars") or language == "HCL":
        patterns.extend(TERRAFORM_PATTERNS)

    for pattern, owasp, name, severity, recommendation in patterns:
        regex = re.compile(pattern)
        for line_no, line in enumerate(lines, start=1):
            if _is_scanner_meta_line(line, name):
                continue
            if regex.search(line):
                findings.append(
                    {
                        "category": owasp,
                        "name": name,
                        "severity": severity,
                        "recommendation": recommendation,
                        "file": path,
                        "line": line_no,
                        "language": language,
                        "snippet": line.strip()[:120],
                        "source": "github_code_scan",
                    }
                )
                break
    return findings


def _guess_language(path: str, repo_languages: dict[str, float]) -> str:
    ext = os.path.splitext(path)[1].lower()
    ext_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".java": "Java",
        ".cs": "C#",
        ".rs": "Rust",
        ".kt": "Kotlin",
        ".swift": "Swift",
        ".sql": "SQL",
        ".sh": "Shell",
        ".bash": "Shell",
        ".tf": "HCL",
        ".hcl": "HCL",
        ".tfvars": "HCL",
    }
    if ext in ext_map:
        return ext_map[ext]
    if repo_languages:
        return max(repo_languages, key=repo_languages.get)
    return "Unknown"


def scan_github_repo(repo_url: str) -> dict[str, Any]:
    """
    Scan a public GitHub repository.
    Returns languages, primary language, files scanned, and code findings.
    """
    owner, repo = parse_github_url(repo_url)
    full_name = f"{owner}/{repo}"

    with httpx.Client() as client:
        languages = fetch_repo_languages(client, owner, repo)
        branch = fetch_default_branch(client, owner, repo)
        paths = list_scannable_files(client, owner, repo, branch, languages)

        findings: list[dict] = []
        for path in paths:
            try:
                content = fetch_file_content(client, owner, repo, path)
            except Exception:
                continue
            if not content:
                continue
            lang = _guess_language(path, languages)
            findings.extend(scan_source_code(content, path, lang))

    primary = max(languages, key=languages.get) if languages else "Unknown"

    return {
        "github_repo": full_name,
        "repo_url": f"https://github.com/{full_name}",
        "default_branch": branch,
        "repo_languages": languages,
        "primary_language": primary,
        "files_scanned": len(paths),
        "code_findings": findings,
    }


def scan_github_repo_safe(repo_url: str) -> dict[str, Any]:
    """Wrapper that returns empty scan on failure instead of raising."""
    try:
        return scan_github_repo(repo_url)
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        if status == 404:
            return {"error": "Repository not found or is private (requires GITHUB_TOKEN)"}
        if status == 403:
            return {"error": "GitHub API rate limit exceeded — set GITHUB_TOKEN"}
        return {"error": f"GitHub API error: {status}"}
    except Exception as e:
        return {"error": str(e)}
