"""Scope and exclusion policy parser for NOVA v2.1."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
WILDCARD_RE = re.compile(
    r"^\*\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


@dataclass
class ProgramPolicy:
    """Represents include and exclude host rules for a single program."""

    program: str
    includes: list[str] = field(default_factory=list)
    exact_excludes: set[str] = field(default_factory=set)
    wildcard_excludes: list[str] = field(default_factory=list)
    regex_excludes: list[re.Pattern] = field(default_factory=list)

    def _matches_exclude(self, host: str) -> bool:
        if host in self.exact_excludes:
            return True
        for suffix in self.wildcard_excludes:
            if host == suffix or host.endswith("." + suffix):
                return True
        return any(rx.search(host) for rx in self.regex_excludes)

    def _matches_include(self, host: str) -> bool:
        for rule in self.includes:
            if rule.startswith("*."):
                base = rule[2:]
                if host == base or host.endswith("." + base):
                    return True
            elif host == rule or host.endswith("." + rule):
                return True
        return False

    def in_scope(self, host_or_url: str) -> bool:
        """Return True when host_or_url is in scope and not excluded."""
        if not host_or_url:
            return False
        raw = host_or_url.strip()
        if "://" in raw:
            host = urlparse(raw).netloc.split("@")[-1].split(":")[0]
        else:
            host = raw.split("/")[0].split("@")[-1].split(":")[0]
        host = host.lower().strip(".")
        if not host:
            return False
        if self._matches_exclude(host):
            return False
        return self._matches_include(host)


def load_program_policy(program: str, targets_dir: Path) -> ProgramPolicy:
    """Parse targets/<program>.txt with support for comments and `!` exclusions."""
    policy = ProgramPolicy(program=program)
    path = targets_dir / f"{program}.txt"
    if not path.exists():
        return policy

    seen_includes = set()
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comment after whitespace+#
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue

        if line.startswith("!"):
            rule = line[1:].strip()
            if rule.lower().startswith("regex:"):
                pattern = rule[6:].strip()
                if pattern:
                    try:
                        policy.regex_excludes.append(re.compile(pattern, re.IGNORECASE))
                    except re.error:
                        pass
            elif rule.startswith("*."):
                suffix = rule[2:].lower().strip(".")
                if suffix:
                    policy.wildcard_excludes.append(suffix)
            else:
                host = rule.lower().strip(".")
                if host:
                    policy.exact_excludes.add(host)
            continue

        host = line.lower().strip(".")
        if host.startswith("*."):
            clean = "*." + host[2:].strip(".")
        else:
            clean = host
        if clean not in seen_includes:
            seen_includes.add(clean)
            policy.includes.append(clean)

    return policy


def audit_target_file(path: Path) -> tuple[str, int, int, list[str]]:
    """Normalize and validate a target file without collapsing explicit subdomains."""
    raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    comments = []
    includes = set()
    excludes = set()
    invalid = []

    for raw_line in raw_lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comments.append(stripped)
            continue
        if stripped.startswith("!"):
            excl = stripped[1:].strip()
            if excl.lower().startswith("regex:"):
                excludes.add("!" + excl)
            elif WILDCARD_RE.match(excl.lower()) or DOMAIN_RE.match(excl.lower()):
                excludes.add("!" + excl.lower())
            else:
                invalid.append(stripped)
            continue

        dom = stripped.lower().strip(".")
        if WILDCARD_RE.match(dom) or DOMAIN_RE.match(dom):
            includes.add(dom)
        else:
            invalid.append(stripped)

    lines = []
    if comments:
        lines.extend(comments)
    lines.extend(sorted(includes))
    lines.extend(sorted(excludes))
    new_content = ("\n".join(lines) + "\n") if lines else ""
    old_content = path.read_text(encoding="utf-8", errors="ignore")
    status = "OK" if old_content == new_content else "FIXED"
    if status == "FIXED":
        path.write_text(new_content, encoding="utf-8")
    return status, len(includes), len(excludes), invalid


def load_focus_programs(targets_dir: Path) -> list[str]:
    """Return curated program names from targets/_focus.txt if configured."""
    focus_file = targets_dir / "_focus.txt"
    if not focus_file.exists():
        return []
    out = []
    for line in focus_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if (targets_dir / f"{item}.txt").exists():
            out.append(item)
    return out
