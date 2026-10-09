#!/usr/bin/env python3
"""Triage as code for Dependabot alerts.

Reads approved exclusion rules from a YAML file, finds open Dependabot alerts
that match them, and dismisses those alerts with the rule's reason and comment.

Dry run unless --apply is given. Design follows pokutuna/dependabot-alert-triage
(rules in YAML, first match wins, recheck before dismiss), extended to run
across a whole organization and to require approval and expiry metadata.

Token (GH_TOKEN): GitHub App installation token with the repository permission
"Dependabot alerts: read and write". The workflow GITHUB_TOKEN cannot dismiss.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import yaml

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REASONS = {"fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk"}
SEVERITIES = {"low", "medium", "high", "critical"}
CLASSIFICATIONS = {"general", "malware"}
MAX_COMMENT = 280  # GitHub limit for dismissed_comment
MAX_RULE_DAYS = 366  # an exclusion must be re-approved at least yearly
RULE_KEYS = {"id", "repo", "match", "classification", "reason", "comment",
             "approved_by", "approved_on", "expires"}
MATCH_KEYS = {"manifest_path", "ecosystem", "packages", "severity"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


# ---------------------------------------------------------------- rules

def glob_to_regex(pattern: str, ignore_case: bool = False) -> re.Pattern:
    """Full-value glob: ** spans directories, * and ? stay within one segment."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(f"^{out}$", re.IGNORECASE if ignore_case else 0)


def normalize_path_pattern(pattern: str) -> str:
    """Alert manifest paths have no leading slash; a trailing slash means 'everything under'."""
    stripped = pattern.lstrip("/")
    if not stripped:
        return "**"
    return stripped + "**" if stripped.endswith("/") else stripped


@dataclass
class Rule:
    id: str
    repo: str | None
    reason: str
    comment: str
    approved_by: str
    approved_on: dt.date
    expires: dt.date
    classification: str = "general"
    manifest_path: str | None = None
    ecosystem: str | None = None
    packages: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)

    def dismissal_comment(self) -> str:
        return (f"[triage:{self.id}] {self.comment} Approved by {self.approved_by} "
                f"on {self.approved_on}, expires {self.expires}.")

    def is_active(self, today: dt.date) -> bool:
        return today <= self.expires

    def matches(self, repo_name: str, alert: dict) -> bool:
        if alert.get("state") != "open":
            return False
        advisory = alert.get("security_advisory") or {}
        if (advisory.get("classification") or "general") != self.classification:
            return False
        if self.repo and not glob_to_regex(self.repo).match(repo_name):
            return False
        dep = alert.get("dependency") or {}
        if self.manifest_path:
            path = dep.get("manifest_path") or ""
            if not glob_to_regex(normalize_path_pattern(self.manifest_path)).match(path):
                return False
        pkg = dep.get("package") or {}
        if self.ecosystem and (pkg.get("ecosystem") or "") != self.ecosystem:
            return False
        if self.packages:
            name = pkg.get("name") or ""
            # Advisories spell names inconsistently (Pillow/pillow), so ignore case here.
            if not any(glob_to_regex(p, ignore_case=True).match(name) for p in self.packages):
                return False
        if self.severity and (advisory.get("severity") or "").lower() not in self.severity:
            return False
        return True


def _as_date(value, where: str) -> dt.date:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"{where}: not a YYYY-MM-DD date: {value!r}") from None


def load_rules(path: str, require_repo: bool, today: dt.date) -> list[Rule]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list):
        raise ValueError(f"{path}: top level must be exactly one key 'rules' holding a list")
    errors: list[str] = []
    rules: list[Rule] = []
    seen: set[str] = set()
    for idx, raw in enumerate(data["rules"]):
        where = f"rules[{idx}]"
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        where = f"rules[{idx}] ({raw.get('id', '?')})"
        unknown = set(raw) - RULE_KEYS
        if unknown:
            errors.append(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("id", "reason", "comment", "approved_by", "approved_on", "expires"):
            if not raw.get(key):
                errors.append(f"{where}: '{key}' is required")
        if errors and errors[-1].startswith(where):
            continue
        match = raw.get("match") or {}
        if not isinstance(match, dict) or set(match) - MATCH_KEYS:
            errors.append(f"{where}: match keys must be among {sorted(MATCH_KEYS)}")
            continue
        try:
            rule = Rule(
                id=str(raw["id"]),
                repo=raw.get("repo"),
                reason=raw["reason"],
                comment=str(raw["comment"]).strip(),
                approved_by=str(raw["approved_by"]),
                approved_on=_as_date(raw["approved_on"], where),
                expires=_as_date(raw["expires"], where),
                classification=raw.get("classification", "general"),
                manifest_path=match.get("manifest_path"),
                ecosystem=match.get("ecosystem"),
                packages=list(match.get("packages") or []),
                severity=[s.lower() for s in (match.get("severity") or [])],
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not ID_RE.match(rule.id):
            errors.append(f"{where}: id must be lowercase letters, digits and dashes")
        if rule.id in seen:
            errors.append(f"{where}: duplicate id")
        seen.add(rule.id)
        if require_repo and not rule.repo:
            errors.append(f"{where}: 'repo' is required when running across an organization")
        if "<" in rule.approved_by or "TODO" in rule.approved_by.upper():
            errors.append(f"{where}: approved_by is still a placeholder; name the approver")
        if rule.reason not in REASONS:
            errors.append(f"{where}: reason must be one of {sorted(REASONS)}")
        if rule.classification not in CLASSIFICATIONS:
            errors.append(f"{where}: classification must be one of {sorted(CLASSIFICATIONS)}")
        if set(rule.severity) - SEVERITIES:
            errors.append(f"{where}: severity values must be among {sorted(SEVERITIES)}")
        if not (rule.manifest_path or rule.packages or rule.ecosystem):
            errors.append(f"{where}: needs at least manifest_path, packages or ecosystem "
                          "(a rule that matches everything is not allowed)")
        if rule.approved_on > today:
            errors.append(f"{where}: approved_on is in the future")
        if rule.expires <= rule.approved_on:
            errors.append(f"{where}: expires must be after approved_on")
        if (rule.expires - rule.approved_on).days > MAX_RULE_DAYS:
            errors.append(f"{where}: expires may be at most {MAX_RULE_DAYS} days after approved_on")
        if len(rule.dismissal_comment()) > MAX_COMMENT:
            errors.append(f"{where}: dismissal comment is {len(rule.dismissal_comment())} chars, "
                          f"GitHub allows {MAX_COMMENT}; shorten 'comment'")
        rules.append(rule)
    if errors:
        raise ValueError("Invalid rules:\n  " + "\n  ".join(errors))
    return rules


# ---------------------------------------------------------------- GitHub API

class GitHub:
    def __init__(self, token: str):
        self.token = token

    def _request(self, method: str, url: str, body: dict | None = None):
        if not url.startswith("http"):
            url = API + url
        req = urllib.request.Request(url, method=method, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dependabot-triage",
        }, data=json.dumps(body).encode() if body is not None else None)
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp), resp.headers.get("Link", "")

    def paginate(self, url: str, limit: int) -> list[dict]:
        items: list[dict] = []
        while url and len(items) < limit:
            page, link = self._request("GET", url)
            items.extend(page)
            nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = nxt.group(1) if nxt else ""
        return items[:limit]

    def open_alerts(self, org: str | None, repos: list[str] | None,
                    limit: int) -> list[tuple[str, dict]]:
        query = "state=open&per_page=100"
        if org:
            alerts = self.paginate(f"/orgs/{org}/dependabot/alerts?{query}", limit)
            return [(a["repository"]["full_name"], a) for a in alerts]
        out: list[tuple[str, dict]] = []
        for repo in repos or []:
            alerts = self.paginate(f"/repos/{repo}/dependabot/alerts?{query}", limit)
            out += [(repo, a) for a in alerts]
        return out

    def get_alert(self, full_repo: str, number: int) -> dict:
        return self._request("GET", f"/repos/{full_repo}/dependabot/alerts/{number}")[0]

    def dismiss(self, full_repo: str, number: int, reason: str, comment: str) -> None:
        self._request("PATCH", f"/repos/{full_repo}/dependabot/alerts/{number}", {
            "state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment})


# ---------------------------------------------------------------- run

def find_candidates(alerts, rules, today):
    active = [r for r in rules if r.is_active(today)]
    out = []
    for full_repo, alert in alerts:
        repo_name = full_repo.split("/", 1)[-1]
        rule = next((r for r in active if r.matches(repo_name, alert)), None)
        if rule:
            out.append((full_repo, alert, rule))
    return out


def write_summary(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def set_output(name: str, value) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=".github/dependabot-triage.yml")
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--org", help="triage every repository in this organization")
    scope.add_argument("--repo", action="append",
                       help="triage this repository, OWNER/NAME (repeatable)")
    ap.add_argument("--apply", action="store_true", help="dismiss alerts (default: dry run)")
    ap.add_argument("--validate-only", action="store_true", help="check the rule file and exit")
    ap.add_argument("--max-alerts", type=int, default=5000)
    args = ap.parse_args(argv)
    today = dt.date.today()

    try:
        rules = load_rules(args.config, require_repo=not args.repo, today=today)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    expired = [r for r in rules if not r.is_active(today)]
    for r in expired:
        print(f"::warning::rule {r.id} expired on {r.expires}; it no longer dismisses alerts. "
              "Renew it (new approval) or delete it.")
    if args.validate_only:
        print(f"{len(rules)} rule(s) valid, {len(expired)} expired.")
        return 0
    if not (args.org or args.repo):
        ap.error("--org or --repo is required unless --validate-only")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("::error::GH_TOKEN is not set", file=sys.stderr)
        return 2

    gh = GitHub(token)
    alerts = gh.open_alerts(args.org, args.repo, args.max_alerts)
    candidates = find_candidates(alerts, rules, today)
    mode = "APPLY" if args.apply else "DRY RUN"
    lines = [f"## Dependabot triage ({mode})", "",
             f"Open alerts read: {len(alerts)}. Matching an active rule: {len(candidates)}.", ""]
    if candidates:
        lines += ["| Repo | Alert | Severity | Package | Manifest | Rule | Result |",
                  "|---|---|---|---|---|---|---|"]

    dismissed, failed = 0, 0
    for full_repo, alert, rule in candidates:
        number = alert["number"]
        dep = alert.get("dependency") or {}
        severity = (alert.get("security_advisory") or {}).get("severity", "")
        result = "would dismiss"
        if args.apply:
            try:
                fresh = gh.get_alert(full_repo, number)  # recheck: still open and still matching
                if not rule.matches(full_repo.split("/", 1)[-1], fresh):
                    result = "skipped (changed)"
                else:
                    gh.dismiss(full_repo, number, rule.reason, rule.dismissal_comment())
                    result = "dismissed"
                    dismissed += 1
            except urllib.error.HTTPError as exc:
                result = f"FAILED HTTP {exc.code}"
                failed += 1
        lines.append(f"| {full_repo} | [#{number}]({alert.get('html_url', '')}) | {severity} "
                     f"| {(dep.get('package') or {}).get('name', '')} "
                     f"| `{dep.get('manifest_path', '')}` | {rule.id} | {result} |")

    write_summary(lines)
    set_output("candidates_count", len(candidates))
    set_output("dismissed_count", dismissed)
    if failed:
        print(f"::error::{failed} alert(s) could not be dismissed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
