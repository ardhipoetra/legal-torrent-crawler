#!/usr/bin/env python3
"""Triage as code for Dependabot alerts.

Reads exclusion rules from a YAML file, finds open Dependabot alerts that match them, 
and dismisses those alerts with the rule's reason and comment.

Dry run unless --apply is provided.

Token (GH_TOKEN): needs "Dependabot alerts: read and write" on the repo.

Require pyyaml. This can be objected to vulnerabilities too. But it should be covered by dependabot itself.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import yaml

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REASONS = {"fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk"}
SEVERITIES = {"low", "medium", "high", "critical"}
CLASSIFICATIONS = {"general", "malware"}
MAX_COMMENT = 280  # GitHub limit for dismissed_comment
RULE_KEYS = {"id", "repo", "match", "classification", "reason", "comment"}
MATCH_KEYS = {"manifest_path", "packages", "severity"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


########## rules ##########

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
    id:             str
    reason:         str = "tolerable_risk"
    repo:           str | None = None
    comment:        str = ""
    classification: str = "general"
    manifest_path:  str | None = None
    packages:       list[str] = field(default_factory=list)
    severity:       list[str] = field(default_factory=list)

    def dismissal_comment(self) -> str:
        return f"[triage:{self.id}] {self.comment}".strip()

    def matches(self, repo_name: str, alert: dict) -> bool:
        # we focus on open alerts
        if alert.get("state") != "open":
            return False

        # that classification is what specified ('general'/'malware')
        advisory = alert.get("security_advisory") or {}
        if (advisory.get("classification") or "general") != self.classification:
            return False
        
        # only on this repository
        if self.repo and not glob_to_regex(self.repo).match(repo_name):
            return False

        dep = alert.get("dependency") or {}
        # the path we want to ignore
        if self.manifest_path:
            path = dep.get("manifest_path") or ""
            if not glob_to_regex(normalize_path_pattern(self.manifest_path)).match(path):
                return False

        # AND the packages to be ignored
        pkg = dep.get("package") or {}
        if self.packages:
            name = pkg.get("name") or ""
            # Advisories spell names inconsistently (Pillow/pillow), so ignore case here.
            if not any(glob_to_regex(p, ignore_case=True).match(name) for p in self.packages):
                return False
        
        # AND if we want to ignore certain severities, check that too
        if self.severity and (advisory.get("severity") or "").lower() not in self.severity:
            return False
        return True

# yaml parsing -> Rule
# including validation too
def load_rules(path: str, require_repo: bool) -> list[Rule]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list):
        raise ValueError(f"{path}: top level must be exactly one key 'rules' holding a list")
    errors: list[str] = []
    rules: list[Rule] = []
    seen: set[str] = set()
    for idx, raw in enumerate(data["rules"]):
        if not isinstance(raw, dict):
            errors.append(f"rules[{idx}]: must be a mapping")
            continue
        where = f"rules[{idx}] ({raw.get('id', '?')})"
        unknown = set(raw) - RULE_KEYS
        if unknown:
            errors.append(f"{where}: unknown keys {sorted(unknown)}")
            continue
        missing = [k for k in ("id", "reason") if not raw.get(k)]
        if missing:
            errors.append(f"{where}: required {missing}")
            continue
        match = raw.get("match") or {}
        if not isinstance(match, dict) or set(match) - MATCH_KEYS:
            errors.append(f"{where}: match keys must be among {sorted(MATCH_KEYS)}")
            continue
        rule = Rule(
            id=str(raw["id"]),
            repo=raw.get("repo"),
            reason=raw["reason"],
            comment=str(raw.get("comment") or "").strip(),
            classification=raw.get("classification", "general"),
            manifest_path=match.get("manifest_path"),
            packages=list(match.get("packages") or []),
            severity=[str(s).lower() for s in (match.get("severity") or [])],
        )
        if not ID_RE.match(rule.id):
            errors.append(f"{where}: id must be lowercase letters, digits and dashes")
        if rule.id in seen:
            errors.append(f"{where}: duplicate id")
        seen.add(rule.id)
        if require_repo and not rule.repo:
            errors.append(f"{where}: 'repo' is required when running across an organization")
        if rule.reason not in REASONS:
            errors.append(f"{where}: reason must be one of {sorted(REASONS)}")
        if rule.classification not in CLASSIFICATIONS:
            errors.append(f"{where}: classification must be one of {sorted(CLASSIFICATIONS)}")
        if set(rule.severity) - SEVERITIES:
            errors.append(f"{where}: severity values must be among {sorted(SEVERITIES)}")
        if not (rule.manifest_path or rule.packages):
            errors.append(f"{where}: needs at least manifest_path or packages "
                          "(a rule that matches everything is not allowed)")
        if len(rule.dismissal_comment()) > MAX_COMMENT:
            errors.append(f"{where}: dismissal comment is {len(rule.dismissal_comment())} chars, "
                          f"GitHub allows {MAX_COMMENT}; shorten 'comment'")
        rules.append(rule)
    if errors:
        raise ValueError("Invalid rules:\n  " + "\n  ".join(errors))
    return rules


########## Github API ##########

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

    # 100 alerts per page, up to limit
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


########## Executions ##########

# find alerts match which rules
def find_candidates(alerts, rules):
    out = []
    for full_repo, alert in alerts:
        repo_name = full_repo.split("/", 1)[-1]
        rule = next((r for r in rules if r.matches(repo_name, alert)), None)
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
    ap.add_argument("--config", default=".github/dependabot-triage-rules.yml")
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--org", help="triage every repository in this organization")
    scope.add_argument("--repo", action="append",
                       help="triage this repository, OWNER/NAME (repeatable)")
    ap.add_argument("--apply", action="store_true", help="dismiss alerts (default: dry run)")
    ap.add_argument("--validate-only", action="store_true", help="check the rule file and exit")
    ap.add_argument("--max-alerts", type=int, default=5000)
    args = ap.parse_args(argv)

    try:
        rules = load_rules(args.config, require_repo=not args.repo)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    if args.validate_only:
        print(f"{len(rules)} rule(s) valid.")
        return 0

    if not (args.org or args.repo):
        ap.error("--org or --repo is required unless --validate-only")

    # get token
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("::error::GH_TOKEN is not set", file=sys.stderr)
        return 2

    gh = GitHub(token)
    alerts = gh.open_alerts(args.org, args.repo, args.max_alerts)
    candidates = find_candidates(alerts, rules)
    mode = "APPLY" if args.apply else "DRY RUN"
    
    # summary to print
    sums_lines = [f"## Dependabot triage ({mode})", "",
             f"Open alerts read: {len(alerts)}. Matching a rule: {len(candidates)}.", ""]


    if candidates:
        sums_lines += [
            "| Repo | Alert | Severity | Package | Manifest | Rule | Result |",
            "|---|---|---|---|---|---|---|"]

    dismissed, failed = 0, 0
    for full_repo, alert, rule in candidates:
        number = alert["number"]
        dep = alert.get("dependency") or {}
        severity = (alert.get("security_advisory") or {}).get("severity", "")
        result = "would dismiss"

        # if we're taking action, recheck the alert
        if args.apply:
            try:
                fresh = gh.get_alert(full_repo, number)  # freshness: still open and match
                if not rule.matches(full_repo.split("/", 1)[-1], fresh):
                    result = "skipped (changed)"
                else:
                    gh.dismiss(full_repo, number, rule.reason, rule.dismissal_comment())
                    result = "dismissed"
                    dismissed += 1
            except urllib.error.HTTPError as exc:
                result = f"FAILED HTTP {exc.code}"
                failed += 1
        sums_lines.append(f"| {full_repo} | [#{number}]({alert.get('html_url', '')}) | {severity} "
                     f"| {(dep.get('package') or {}).get('name', '')} "
                     f"| `{dep.get('manifest_path', '')}` | {rule.id} | {result} |")

    write_summary(sums_lines)
    set_output("candidates_count", len(candidates))
    set_output("dismissed_count", dismissed)

    if failed:
        print(f"::error::{failed} alert(s) could not be dismissed", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
