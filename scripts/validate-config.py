#!/usr/bin/env python3
"""Protect this fork's config from Cloud Run drift and upstream env-code changes.

Commands:
  check              Fail if live Cloud Run differs from protected-config.yml.
  snapshot           Dump live Cloud Run env/secrets as lockfile YAML.
  check-code         Fail if env.py/config.py keys or defaults changed, or if a
                     locked Cloud Run key is no longer read in those files.
  snapshot-code      Dump current env.py/config.py getenv inventory.

The deploy workflow runs check-code first (no GCP needed), then the Cloud Run
checks. It never updates env or secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required. Install with: pip install pyyaml\n")
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "protected-config.yml"
DEFAULT_CODE_LOCK = REPO_ROOT / "config-code-lock.yml"
CODE_FILES = [
    REPO_ROOT / "backend" / "open_webui" / "env.py",
    REPO_ROOT / "backend" / "open_webui" / "config.py",
]
GETENV_START = re.compile(r"os\.(getenv|environ\.get)\(\s*")
REDACT_KEY = re.compile(
    r"(SECRET|PASSWORD|TOKEN|API_KEY|REDIS_URL|DATABASE_URL|CLIENT_ID|CLIENT_SECRET|TENANT)",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = {"", "REPLACE_FROM_SNAPSHOT", "replace_from_snapshot", "null", "None"}


def load_lockfile(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Lockfile not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Lockfile is not a YAML object: {path}")
    if "protected" in data and "env" not in data and "secrets" not in data:
        raise SystemExit(
            "Old protected-config.yml format detected. Use env: and secrets: keys, "
            "not a single protected: map."
        )
    return data


def stringify(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return ""
    return str(value)


def should_redact(name: str) -> bool:
    return bool(REDACT_KEY.search(name))


def display_value(name: str, value: str) -> str:
    if should_redact(name):
        return "<redacted>"
    return value


def run_gcloud(args: list[str]) -> str:
    result = subprocess.run(
        ["gcloud", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SystemExit(f"gcloud {' '.join(args)} failed:\n{detail}")
    return result.stdout


def resolve_cloud_run(lock: dict[str, Any]) -> tuple[str, str, str]:
    meta = lock.get("cloud_run") or {}
    project = os.getenv("PROJECT_ID") or meta.get("project")
    region = os.getenv("REGION") or meta.get("region")
    service = os.getenv("SERVICE") or meta.get("service")
    missing = [
        name
        for name, value in (
            ("project", project),
            ("region", region),
            ("service", service),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f"Missing Cloud Run {', '.join(missing)} in lockfile or env")
    return str(project), str(region), str(service)


def parse_env_list(env_list: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    env: dict[str, str] = {}
    secrets: dict[str, str] = {}
    for item in env_list:
        name = item.get("name")
        if not name:
            continue

        secret_ref = (item.get("valueFrom") or {}).get("secretKeyRef") or {}
        if not secret_ref:
            secret_ref = (item.get("valueSource") or {}).get("secretKeyRef") or {}

        secret_name = secret_ref.get("name") or secret_ref.get("secret")
        version = secret_ref.get("key") or secret_ref.get("version") or "latest"
        if secret_name:
            secrets[name] = f"{secret_name}:{version}"
        else:
            env[name] = stringify(item.get("value", ""))
    return env, secrets


def container_env_from_resource(resource: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    spec = resource.get("spec") or {}
    containers = (
        spec.get("template", {}).get("spec", {}).get("containers")  # Service (Knative v1)
        or spec.get("containers")  # Revision (Knative v1)
        or resource.get("template", {}).get("containers")  # Service (Cloud Run v2)
        or resource.get("containers")  # Revision (Cloud Run v2)
        or []
    )
    if not containers:
        raise SystemExit("Could not find a Cloud Run container spec to read env from")
    return parse_env_list(containers[0].get("env") or [])


def describe_service(project: str, region: str, service: str) -> dict[str, Any]:
    raw = run_gcloud(
        [
            "run",
            "services",
            "describe",
            service,
            f"--project={project}",
            f"--region={region}",
            "--format=json",
        ]
    )
    return json.loads(raw)


def describe_latest_revision(project: str, region: str, service: str) -> dict[str, Any]:
    service_json = describe_service(project, region, service)
    revision = (service_json.get("status") or {}).get("latestCreatedRevisionName")
    if not revision:
        raise SystemExit("Cloud Run service has no latestCreatedRevisionName")
    raw = run_gcloud(
        [
            "run",
            "revisions",
            "describe",
            revision,
            f"--project={project}",
            f"--region={region}",
            "--format=json",
        ]
    )
    resource = json.loads(raw)
    resource["_revision_name"] = revision
    return resource


def expected_maps(lock: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    env = {str(k): stringify(v) for k, v in (lock.get("env") or {}).items()}
    secrets = {str(k): stringify(v) for k, v in (lock.get("secrets") or {}).items()}
    overlap = set(env) & set(secrets)
    if overlap:
        raise SystemExit(f"Keys present in both env and secrets: {sorted(overlap)}")
    return env, secrets


def collect_errors(
    expected_env: dict[str, str],
    expected_secrets: dict[str, str],
    live_env: dict[str, str],
    live_secrets: dict[str, str],
    fail_on_extra: bool,
) -> list[str]:
    errors: list[str] = []
    expected_keys = set(expected_env) | set(expected_secrets)
    live_keys = set(live_env) | set(live_secrets)

    for key, expected in expected_env.items():
        if key in live_secrets:
            errors.append(f"{key}: expected plain env value, but Cloud Run binds a secret")
            continue
        actual = live_env.get(key)
        if actual is None:
            errors.append(f"{key}: missing on Cloud Run (expected env '{display_value(key, expected)}')")
        elif expected in PLACEHOLDER_VALUES:
            errors.append(
                f"{key}: lockfile still has placeholder '{expected}'. "
                "Run snapshot-config and commit the result."
            )
        elif actual != expected:
            errors.append(
                f"{key}: expected '{display_value(key, expected)}', "
                f"found '{display_value(key, actual)}'"
            )

    for key, expected in expected_secrets.items():
        if key in live_env:
            errors.append(f"{key}: expected secret binding, but Cloud Run has a plain env value")
            continue
        actual = live_secrets.get(key)
        if actual is None:
            errors.append(f"{key}: missing secret binding (expected {expected})")
        elif actual != expected:
            errors.append(f"{key}: expected secret '{expected}', found '{actual}'")

    extra = sorted(live_keys - expected_keys)
    if fail_on_extra and extra:
        for key in extra:
            errors.append(f"{key}: extra key on Cloud Run that is not in the lockfile")

    return errors


def cmd_check(args: argparse.Namespace) -> int:
    lock = load_lockfile(args.config)
    project, region, service = resolve_cloud_run(lock)
    expected_env, expected_secrets = expected_maps(lock)
    fail_on_extra = bool((lock.get("options") or {}).get("fail_on_extra_keys", True))

    if args.latest_revision:
        resource = describe_latest_revision(project, region, service)
        source = f"revision {resource.get('_revision_name')}"
    else:
        resource = describe_service(project, region, service)
        source = f"service {service}"

    live_env, live_secrets = container_env_from_resource(resource)
    errors = collect_errors(
        expected_env,
        expected_secrets,
        live_env,
        live_secrets,
        fail_on_extra,
    )

    print(f"Checking {source} in {project}/{region} against {args.config}")
    if errors:
        print("")
        print("PROTECTED CONFIGURATION CHECK FAILED")
        print("")
        for error in errors:
            print(f"  - {error}")
        print("")
        print("Deployment stopped. Cloud Run env/secrets must match protected-config.yml.")
        print("If this change is intentional, update the lockfile and commit it.")
        return 1

    print("All protected configuration values match.")
    return 0


def lockfile_document(project: str, region: str, service: str, env: dict[str, str], secrets: dict[str, str]) -> dict[str, Any]:
    return {
        "cloud_run": {
            "project": project,
            "region": region,
            "service": service,
        },
        "options": {
            "fail_on_extra_keys": True,
        },
        "env": dict(sorted(env.items())),
        "secrets": dict(sorted(secrets.items())),
    }


def skip_ws_and_comments(text: str, i: int) -> int:
    while i < len(text):
        if text[i] in " \t\r\n":
            i += 1
            continue
        if text.startswith("#", i):
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        break
    return i


def read_python_string(text: str, i: int) -> tuple[str | None, int]:
    i = skip_ws_and_comments(text, i)
    if i >= len(text) or text[i] not in "'\"":
        return None, i
    quote = text[i]
    i += 1
    chars: list[str] = []
    while i < len(text):
        char = text[i]
        if char == "\\":
            chars.append(char)
            if i + 1 < len(text):
                chars.append(text[i + 1])
                i += 2
                continue
            i += 1
            continue
        if char == quote:
            return "".join(chars), i + 1
        chars.append(char)
        i += 1
    return None, i


def read_balanced_expr(text: str, i: int) -> tuple[str | None, int]:
    depth = 1
    start = i
    while i < len(text):
        char = text[i]
        if char in "'\"":
            _, next_i = read_python_string(text, i)
            if next_i == i:
                return None, i
            i = next_i
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:i].strip(), i + 1
        i += 1
    return None, i


def normalize_default(raw: str) -> str:
    return re.sub(r"\s+", " ", raw).strip()


def scan_getenv_calls(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in GETENV_START.finditer(text):
        i = match.end()
        key, i = read_python_string(text, i)
        if not key:
            continue
        i = skip_ws_and_comments(text, i)
        default = "<missing>"
        if i < len(text) and text[i] == ",":
            expr, i = read_balanced_expr(text, i + 1)
            default = normalize_default(expr) if expr is not None else "<unparsed>"
        else:
            default = "<unset>"
        found.append((key, default))
    return found


def scan_code_env() -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for path in CODE_FILES:
        if not path.exists():
            raise SystemExit(f"Config source not found: {path}")
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for key, default in scan_getenv_calls(text):
            entry = inventory.setdefault(key, {"defaults": [], "files": []})
            if default not in entry["defaults"]:
                entry["defaults"].append(default)
            if rel not in entry["files"]:
                entry["files"].append(rel)
    for entry in inventory.values():
        entry["defaults"].sort()
        entry["files"].sort()
    return dict(sorted(inventory.items()))


def code_lock_document(inventory: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_files": [path.relative_to(REPO_ROOT).as_posix() for path in CODE_FILES],
        "keys": inventory,
    }


def load_code_lock(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(
            f"Code lockfile not found: {path}\n"
            "Run: python scripts/validate-config.py snapshot-code --write"
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or "keys" not in data:
        raise SystemExit(f"Invalid code lockfile: {path}")
    return data


def collect_code_errors(
    expected: dict[str, dict[str, Any]],
    actual: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    expected_keys = set(expected)
    actual_keys = set(actual)

    for key in sorted(expected_keys - actual_keys):
        errors.append(f"{key}: removed from env.py/config.py (renamed or deleted)")

    for key in sorted(actual_keys - expected_keys):
        defaults = ", ".join(actual[key].get("defaults") or ["<unknown>"])
        errors.append(f"{key}: new env key in env.py/config.py (default {defaults})")

    for key in sorted(expected_keys & actual_keys):
        old_defaults = expected[key].get("defaults") or []
        new_defaults = actual[key].get("defaults") or []
        if old_defaults != new_defaults:
            errors.append(
                f"{key}: default changed from {old_defaults} to {new_defaults}"
            )
    return errors


def collect_locked_key_errors(
    lock: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    not_in_code = {
        str(key) for key in ((lock.get("options") or {}).get("not_in_code") or [])
    }
    locked = set((lock.get("env") or {}) | (lock.get("secrets") or {}))
    for key in sorted(locked):
        if key in not_in_code:
            continue
        if key not in inventory:
            errors.append(
                f"{key}: locked Cloud Run key is no longer read in env.py/config.py"
            )
    return errors


def cmd_check_code(args: argparse.Namespace) -> int:
    lock = load_lockfile(args.config)
    expected = load_code_lock(args.code_lock).get("keys") or {}
    actual = scan_code_env()
    errors = collect_code_errors(expected, actual)
    errors.extend(collect_locked_key_errors(lock, actual))

    print(f"Checking env.py/config.py against {args.code_lock}")
    if errors:
        print("")
        print("UPSTREAM CONFIG CODE CHECK FAILED")
        print("")
        for error in errors:
            print(f"  - {error}")
        print("")
        print("Deployment stopped. Review the env.py/config.py change.")
        print("If it is intentional, run snapshot-code --write, inspect the diff, and commit.")
        return 1

    print("All env.py/config.py keys and defaults match the code lockfile.")
    print("All locked Cloud Run keys are still read in code.")
    return 0


def cmd_snapshot_code(args: argparse.Namespace) -> int:
    inventory = scan_code_env()
    document = code_lock_document(inventory)
    rendered = yaml.safe_dump(
        document,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    if args.write:
        args.code_lock.write_text(rendered, encoding="utf-8")
        print(f"Wrote {len(inventory)} env keys to {args.code_lock}")
    else:
        sys.stdout.write(rendered)
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    lock = load_lockfile(args.config) if args.config.exists() else {}
    project, region, service = resolve_cloud_run(lock if lock else {"cloud_run": {}})
    resource = describe_service(project, region, service)
    live_env, live_secrets = container_env_from_resource(resource)
    document = lockfile_document(project, region, service, live_env, live_secrets)
    rendered = yaml.safe_dump(
        document,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    if args.write:
        args.config.write_text(rendered, encoding="utf-8")
        print(f"Wrote live Cloud Run config to {args.config}")
    else:
        sys.stdout.write(rendered)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Protect Cloud Run env from unintended changes")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Path to protected-config.yml",
    )
    parser.add_argument(
        "--code-lock",
        type=Path,
        default=DEFAULT_CODE_LOCK,
        help="Path to config-code-lock.yml",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Fail if live Cloud Run differs from the lockfile")
    check.add_argument(
        "--latest-revision",
        action="store_true",
        help="Compare against the latest created revision instead of the serving service",
    )
    check.set_defaults(func=cmd_check)

    snapshot = sub.add_parser("snapshot", help="Dump live Cloud Run env/secrets as lockfile YAML")
    snapshot.add_argument(
        "--write",
        action="store_true",
        help="Overwrite the lockfile instead of printing YAML",
    )
    snapshot.set_defaults(func=cmd_snapshot)

    check_code = sub.add_parser(
        "check-code",
        help="Fail if env.py/config.py keys/defaults changed, or a locked key vanished",
    )
    check_code.set_defaults(func=cmd_check_code)

    snapshot_code = sub.add_parser(
        "snapshot-code",
        help="Dump current env.py/config.py getenv inventory",
    )
    snapshot_code.add_argument(
        "--write",
        action="store_true",
        help="Overwrite config-code-lock.yml",
    )
    snapshot_code.set_defaults(func=cmd_snapshot_code)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
