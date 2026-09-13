#!/usr/bin/env python3
"""
agentmode.py, Beacon Collector continuous mode for agentic AI deployments (v0.1).

The missing edge of the triangle: signed declaration -> transparency log ->
CONTINUOUS RUNTIME ATTESTATION. This module is the third vertex, dogfooded
first on the household deployment it runs inside.

What it does:
  - Collects the 17-element agent evidence schedule (Annex A, Emily letter
    2026-08-16) for a PAI-style agentic deployment: model, harness, tool/MCP,
    containment, data/memory, change/time, observability layers.
  - Watches the deployment's CONFIG surfaces (not its data) via a fast digest;
    seals a fresh package on any change, and on a periodic heartbeat even
    without change (element 15: the seal gap is the honesty of the system).
  - Hash-chains every package to the previous one (prev_package_hash inside
    the sealed core), so the local chain is transparency-log-ready: anchoring
    a chain head to Rekor/SCITT later anchors the whole history.

Invariants inherited from the chassis (SPEC.md, Joshua's calls 2026-07-28):
  - NEVER rates. Facts only; absence recorded as absence (facts-of-absence
    are facts). Leveling belongs to the scorer/CRC downstream.
  - Metadata over content: prompts and configs are captured as HASHES and
    inventories; no secrets, no message content, no memory content.
  - Seal = trust anchor: per-item item_sha256, package_hash, Ed25519 identity
    signature when the enrolled key is reachable; UNSIGNED sealing (declared)
    when it is not, e.g. keychain locked at headless boot.

Usage:
  agentmode.py tick [--home DIR] [--state DIR]     # cron/launchd entry: seal if changed or heartbeat due
  agentmode.py collect --reason manual [...]       # force a seal now
  agentmode.py verify-chain [--state DIR]          # verify every package + chain linkage
  agentmode.py status [--state DIR]                # one-screen state
"""
import argparse
import glob
import json
import os
import platform
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import beaconlib as bl
from beaconlib import canonical, sha256, utcnow, completeness

VERSION = "0.1.0"
HEARTBEAT_SECONDS = 6 * 3600
DEFAULT_STATE = "~/.beacon/agent"
DEFAULT_HOME = "~/.beacon"
KEYCHAIN_SERVICE = "beacon-agent-passphrase"

H = os.path.expanduser

# ---- Config surfaces: the change-triggers. Config only, never data layers
# (journals/memory churn constantly; they are REPORTED at seal time, but do
# not trigger re-seals; element F14/F15 carry the change story).
WATCHED_SURFACES = {
    "harness-settings":  ["~/.claude/settings.json", "~/.claude/.mcp.json"],
    "system-prompts":    ["~/.claude/CLAUDE.md", "~/.claude/skills/PAI/SKILL.md",
                          "~/.claude/CAIRN/CORE.md"],
    "hooks":             ["~/.claude/hooks/*.hook.ts"],
    "launchd-jobs":      ["~/Library/LaunchAgents/*.plist"],
    "ssh-surface":       ["~/.ssh/config", "~/.ssh/authorized_keys"],
    "agent-definitions": ["~/.claude/agents/*.md"],
}


def file_sha(path):
    try:
        with open(path, "rb") as f:
            return sha256(f.read())
    except OSError:
        return None


def expand(globs):
    out = []
    for g in globs:
        out.extend(sorted(glob.glob(H(g))))
    return [p for p in out if os.path.isfile(p)]


def surface_digest():
    """{surface: {"files": {path: sha}, "digest": sha-of-manifest}}"""
    result = {}
    for name, globs in WATCHED_SURFACES.items():
        files = {p: file_sha(p) for p in expand(globs)}
        result[name] = {"files": files, "digest": sha256(canonical(files))}
    return result


def run(cmd, timeout=10):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def port_open(port, host="127.0.0.1", timeout=0.3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def load_json(path):
    try:
        with open(H(path)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---------------- The 17 elements, mapped to THIS deployment ----------------
# Each returns an observation dict of mechanical facts. Absence is recorded,
# never skipped. No content, no secrets: hashes, names, counts, ages.

def obs_a1_model_identity(fx):
    settings = load_json("~/.claude/settings.json") or {}
    endpoints = []
    model = settings.get("model")
    if model:
        endpoints.append({"endpoint": "claude-code-harness", "model_id": str(model),
                          "source": "settings.json:model"})
    env_model = os.environ.get("ANTHROPIC_MODEL")
    if env_model:
        endpoints.append({"endpoint": "env", "model_id": env_model, "source": "ANTHROPIC_MODEL"})
    proxy = port_open(11435)
    ollama = port_open(11434)
    if proxy:
        endpoints.append({"endpoint": "inference-proxy:11435", "model_id": "routing-proxy (simple->local, complex->api)",
                          "source": "tcp-probe"})
    if ollama:
        endpoints.append({"endpoint": "ollama:11434", "model_id": "local (models enumerable via API)",
                          "source": "tcp-probe"})
    return {"endpoints": {"present": bool(endpoints), "list": endpoints},
            "local_inference": {"present": True, "proxy_11435_listening": proxy,
                                "ollama_11434_listening": ollama},
            "note": "session-level model is asserted by the harness at runtime; config-level identity recorded here"}


def obs_a2_response_fingerprints(fx):
    return {"fingerprint_sampling": {"present": False,
            "note": "no response-metadata middleware tap deployed in this household; "
                    "absence recorded as absence (Annex element 2 confidence MEDIUM, "
                    "field availability varies by provider)"}}


def obs_a3_model_parameters(fx):
    settings = load_json("~/.claude/settings.json") or {}
    path = H("~/.claude/settings.json")
    keys = sorted(settings.keys()) if settings else []
    return {"config_in_force": {"present": bool(keys), "top_level_keys": keys,
                                "file_sha256": file_sha(path)},
            "extracted": {"present": True,
                          "model": settings.get("model"),
                          "note": "full values withheld by design (settings may embed env/secrets); "
                                  "hash proves what was in force"}}


# Where to look for agent tooling. launchd hands scheduled jobs a minimal PATH,
# so probing bare command names measures the COLLECTOR's environment rather than
# the environment the agents actually run in. Until 2026-08-26 this collector
# sealed "bun: missing" and "claude-code: missing" as facts while both were
# installed. An absence is only meaningful relative to a stated search scope, so
# the scope is now widened AND recorded in the observation.
PROBE_PATH = [
    H("~/.bun/bin"), H("~/.local/bin"), H("~/.cargo/bin"),
    "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
]


def which_in(name, search=None):
    for d in (search or PROBE_PATH):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def obs_b4_framework_versions(fx):
    probes = {"claude-code": "claude", "bun": "bun", "python3": "python3", "git": "git"}
    versions, resolved, missing = {}, {}, []
    for label, binary in probes.items():
        path = which_in(binary)
        if path is None:
            missing.append(label)
            continue
        v = run([path, "--version"])
        if v:
            versions[label] = v
            resolved[label] = path
        else:
            missing.append(label)

    return {"harness_versions": {
                "present": bool(versions),
                "versions": versions,
                "resolved_paths": resolved,
                "missing": sorted(missing),
                "search_path": PROBE_PATH,
                "note": "absence is relative to search_path; the collector runs under "
                        "launchd with a minimal environment PATH, so search_path is "
                        "stated explicitly rather than inherited",
                "collector_env_path": os.environ.get("PATH", ""),
            },
            "os": {"present": True, "platform": platform.platform()}}


def obs_b5_agent_definitions(fx):
    agents = fx["surfaces"].get("agent-definitions", {}).get("files", {})
    skills_dir = H("~/.claude/skills")
    skills = sorted(os.listdir(skills_dir)) if os.path.isdir(skills_dir) else []
    return {"agent_definition_files": {"present": bool(agents), "count": len(agents),
                                       "manifest_sha256": sha256(canonical(agents))},
            "skills_inventory": {"present": bool(skills), "count": len(skills),
                                 "names": skills},
            "note": "agent graph = PAI skills + agent definition files; hashes in raw blob"}


def obs_b6_system_prompts(fx):
    prompts = fx["surfaces"].get("system-prompts", {}).get("files", {})
    return {"prompt_hashes": {"present": bool(prompts), "count": len(prompts),
                              "files": {os.path.basename(p): h for p, h in prompts.items()},
                              "note": "cleartext stays in the deployment; hash proves what was in force"}}


def obs_c7_mcp_inventory(fx):
    mcp = load_json("~/.claude/.mcp.json") or {}
    servers = mcp.get("mcpServers", mcp) if isinstance(mcp, dict) else {}
    inv = []
    for name, cfg in (servers.items() if isinstance(servers, dict) else []):
        if not isinstance(cfg, dict):
            continue
        entry = {"name": name,
                 "transport": "url" if cfg.get("url") else "stdio",
                 "command": cfg.get("command")}
        cmd_path = cfg.get("command")
        if cmd_path and os.path.isfile(H(cmd_path)):
            entry["command_sha256"] = file_sha(H(cmd_path))
        args = cfg.get("args") or []
        for a in args:
            if isinstance(a, str) and os.path.isfile(H(a)):
                entry["server_file"] = a
                entry["server_file_sha256"] = file_sha(H(a))
                break
        inv.append(entry)
    return {"mcp_servers": {"present": bool(inv), "count": len(inv), "servers": inv,
                            "config_sha256": file_sha(H("~/.claude/.mcp.json"))},
            "upstream_provenance": {"present": False,
                                    "note": "registry signature ecosystems immature (Annex element 7 MEDIUM); local hashes only"}}


def obs_c8_permission_surface(fx):
    settings = load_json("~/.claude/settings.json") or {}
    perms = settings.get("permissions", {}) if isinstance(settings, dict) else {}
    ak = H("~/.ssh/authorized_keys")
    ak_count = 0
    if os.path.isfile(ak):
        with open(ak) as f:
            ak_count = sum(1 for line in f if line.strip() and not line.startswith("#"))
    return {"harness_permissions": {"present": bool(perms),
                                    "allow_rules": len(perms.get("allow", []) or []),
                                    "deny_rules": len(perms.get("deny", []) or []),
                                    "ask_rules": len(perms.get("ask", []) or [])},
            "remote_access": {"present": True, "authorized_ssh_keys": ak_count,
                              "sshd_hardening_config_sha256": file_sha(H("~/.ssh/sshd-hardening.conf"))},
            "note": "cloud IAM not applicable to this deployment; recorded as out-of-scope for household"}


def obs_c9_identity_credentials(fx):
    now = time.time()
    keys = []
    ssh_dir = H("~/.ssh")
    if os.path.isdir(ssh_dir):
        for p in sorted(glob.glob(os.path.join(ssh_dir, "*.pub"))):
            age_days = round((now - os.path.getmtime(p)) / 86400)
            keys.append({"key": os.path.basename(p), "age_days": age_days})
    enrollment = load_json(os.path.join(DEFAULT_HOME, "enrollment.json"))
    return {"ssh_key_inventory": {"present": bool(keys), "count": len(keys), "keys": keys,
                                  "note": "age = mtime age; rotation policy not automated (fact, not judgment)"},
            "collector_identity": {"present": bool(enrollment),
                                   "collector_id": (enrollment or {}).get("collector_id"),
                                   "key_fingerprint": (enrollment or {}).get("key_fingerprint")},
            "agent_registry": {"present": False,
                               "note": "no ANS-style registry live yet; forward-links to the registry work"}}


def obs_d10_guardrails(fx):
    hooks = fx["surfaces"].get("hooks", {}).get("files", {})
    names = sorted(os.path.basename(p) for p in hooks)
    settings = load_json("~/.claude/settings.json") or {}
    return {"guardrail_hooks": {"present": bool(hooks), "count": len(hooks),
                                "names": names,
                                "manifest_sha256": sha256(canonical(hooks))},
            "hook_wiring": {"present": "hooks" in settings,
                            "note": "hook config lives in settings.json (hashed in element 3)"}}


def observed_egress():
    """A point-in-time sample of who this user's processes are talking to.

    The claimed/provable pair for the tool layer: an MCP server or agent DECLARES
    what it may reach, and this observes what was actually open at one instant.
    Unprivileged, so it sees this user's own processes, which is exactly the set
    the agents run as.

    This is a SAMPLE and the record says so in the data itself. A connection that
    opens and closes between two seals is never seen, so absence here is not
    evidence that nothing was reached. Overstating coverage would be worse than
    collecting nothing, because it would teach a reader that our absences mean
    something they do not.
    """
    # Field mode, not the human table: command names can contain spaces (and on
    # this host the harness presents as a bare version string), which shifts
    # positional columns and silently mis-attributes connections.
    out = run(["lsof", "-i", "-n", "-P", "-F", "pcnPtT"], timeout=20)
    if out is None:
        return {"present": False, "method": "lsof",
                "note": "lsof unavailable or returned no data; absence recorded as absence"}

    conns, hosts = [], set()
    pid = cmd = proto = fam = name = state = None
    for line in out.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid, cmd = val, None
        elif tag == "c":
            cmd = val
        elif tag == "t":
            fam = val
        elif tag == "P":
            proto = val
        elif tag == "n":
            name = val
        elif tag == "T":
            if val.startswith("ST="):
                state = val[3:]
                if name and "->" in name and state == "ESTABLISHED":
                    remote = name.partition("->")[2]
                    remote_host = remote.rsplit(":", 1)[0]
                    # Loopback and link-local are local plumbing, not egress.
                    if not remote_host.startswith(("127.", "[::1", "fe80", "[fe80")):
                        conns.append({"process": cmd, "pid": pid, "remote": remote,
                                      "protocol": proto, "family": fam})
                        hosts.add(remote_host)

    return {
        "present": True,
        "method": "lsof -i -n -P -F pcnPtT",
        "observation_type": "point_in_time_sample",
        "privilege": "unprivileged; covers this user's processes only",
        "established_count": len(conns),
        "distinct_remote_hosts": len(hosts),
        "connections": sorted(conns, key=lambda c: (c["process"], c["remote"]))[:200],
        "completeness_caveat": ("single instantaneous sample at seal time. Connections opened "
                               "and closed between seals are NOT observed. Absence of a remote "
                               "host here is not evidence it was never contacted."),
        "not_collected": "no payload, no DNS queries, no traffic content, no volume",
    }


def obs_d11_isolation_egress(fx):
    plists = fx["surfaces"].get("launchd-jobs", {}).get("files", {})
    names = sorted(os.path.basename(p) for p in plists)
    return {"scheduled_execution_surface": {"present": bool(plists), "count": len(plists),
                                            "jobs": names,
                                            "manifest_sha256": sha256(canonical(plists))},
            "egress_allowlist": {"present": False,
                                 "note": "no network egress allowlist enforced at host level; absence recorded"},
            "observed_egress_sample": observed_egress(),
            "sandbox": {"present": True,
                        "note": "harness-level command sandboxing + permission prompts in force (config hashed in element 3)"}}



def pai_memory_dir() -> str:
    """Locate the PAI memory corpus.

    BEACON_PAI_MEMORY overrides. Otherwise the single project directory under
    ~/.claude/projects that carries a memory/ subdir is used, so the module is
    not pinned to one operator's home path. Returns a non-existent path rather
    than raising; callers already treat absence as a fact of absence.
    """
    env = os.environ.get("BEACON_PAI_MEMORY")
    if env:
        return H(env)
    root = H("~/.claude/projects")
    try:
        cands = [d for d in glob.glob(os.path.join(root, "*", "memory"))
                 if os.path.isdir(d) and os.path.isfile(os.path.join(d, "MEMORY.md"))]
    except OSError:
        cands = []
    if not cands:
        return os.path.join(root, "unknown", "memory")
    # Richest corpus wins, then lexical, so the choice is deterministic across runs.
    return sorted(cands, key=lambda d: (-len(glob.glob(os.path.join(d, "**", "*.md"),
                                                       recursive=True)), d))[0]


def obs_e12_rag_provenance(fx):
    mem_dir = pai_memory_dir()
    files = glob.glob(os.path.join(mem_dir, "**", "*.md"), recursive=True)
    total = sum(os.path.getsize(p) for p in files) if files else 0
    return {"vector_store": {"present": False,
                             "note": "no vector/RAG store deployed; memory is file-based markdown"},
            "memory_corpus_cursor": {"present": bool(files), "file_count": len(files),
                                     "total_bytes": total,
                                     "index_sha256": file_sha(os.path.join(mem_dir, "MEMORY.md"))}}


def obs_e13_memory_state(fx):
    mem_index = os.path.join(pai_memory_dir(), "MEMORY.md")
    return {"memory_stores": {"present": True,
                              "stores": ["file-based memory (markdown + index)",
                                         "MEMORY/STATE mailboxes (jsonl)",
                                         "CAIRN identity files"],
                              "index_sha256": file_sha(mem_index),
                              "index_bytes": os.path.getsize(mem_index) if os.path.isfile(mem_index) else 0},
            "retention": {"present": True,
                          "note": "memory-permanence standard: demotion never deletion; hourly backup + 09:30/21:30 verify (launchd jobs in element 11)"}}


def obs_f14_change_events(fx):
    repos = []
    for repo in [os.path.dirname(os.path.abspath(__file__))]:
        sha = run(["git", "-C", repo, "rev-parse", "HEAD"])
        if sha:
            dirty = run(["git", "-C", repo, "status", "--porcelain"])
            repos.append({"repo": repo, "head": sha, "dirty": bool(dirty)})
    digests = {name: s["digest"] for name, s in fx["surfaces"].items()}
    return {"vcs_state": {"present": bool(repos), "repos": repos,
                          "note": "~/.claude itself is not a git repo; config-surface digests below are the change fingerprint"},
            "config_surface_digests": {"present": True, "digests": digests}}


def obs_f15_seal_cadence(fx):
    log_path = fx["seal_log_path"]
    entries = []
    if os.path.isfile(log_path):
        with open(log_path) as f:
            entries = [json.loads(line) for line in f if line.strip()]
    reasons = {}
    for e in entries:
        reasons[e.get("reason", "?")] = reasons.get(e.get("reason", "?"), 0) + 1
    last = entries[-1] if entries else None
    return {"seal_history": {"present": bool(entries), "count": len(entries),
                             "by_reason": reasons,
                             "last_seal_utc": last.get("utc") if last else None},
            "cadence_policy": {"present": True,
                               "change_triggered": True,
                               "heartbeat_seconds": HEARTBEAT_SECONDS,
                               "note": "the gap between last seal and any incident is always disclosed; it is the honesty of the system"}}


def obs_g16_log_surface(fx):
    log_dir = H("~/.claude/CAIRN/logs")
    logs = glob.glob(os.path.join(log_dir, "*.log")) if os.path.isdir(log_dir) else []
    total = sum(os.path.getsize(p) for p in logs) if logs else 0
    newest = max((os.path.getmtime(p) for p in logs), default=None)
    rotated = glob.glob(os.path.join(log_dir, "*.gz")) + glob.glob(os.path.join(log_dir, "*.log.[0-9]*"))
    return {"log_inventory": {"present": bool(logs), "count": len(logs),
                              "total_bytes": total,
                              "newest_age_seconds": round(time.time() - newest) if newest else None,
                              "location": log_dir},
            "integrity_protection": {"present": False,
                                     "note": "logs are plain files, no append-only/integrity protection; absence recorded"},
            "rotation": {"present": bool(rotated), "rotated_artifacts": len(rotated)}}


def obs_g17_eval_results(fx):
    candidates = ["~/.claude/skills/Evals", "~/.claude/Workspaces/ValueChainInstitute/BeaconScore"]
    found = []
    for c in candidates:
        d = H(c)
        if os.path.isdir(d):
            found.append({"path": c, "entries": len(os.listdir(d))})
    return {"eval_runs": {"present": False,
                          "note": "no standing eval-run artifacts at known paths; eval frameworks installed but no sealed run history",
                          "searched": candidates, "dirs_present": found}}


ELEMENTS = [
    ("agent-v0:A1",  "model",         "model-identity-per-endpoint", obs_a1_model_identity, ["endpoints", "local_inference"]),
    ("agent-v0:A2",  "model",         "response-version-fingerprints", obs_a2_response_fingerprints, ["fingerprint_sampling"]),
    ("agent-v0:A3",  "model",         "model-parameters-in-force", obs_a3_model_parameters, ["config_in_force", "extracted"]),
    ("agent-v0:B4",  "harness",       "framework-and-version", obs_b4_framework_versions, ["harness_versions", "os"]),
    ("agent-v0:B5",  "harness",       "agent-definitions", obs_b5_agent_definitions, ["agent_definition_files", "skills_inventory"]),
    ("agent-v0:B6",  "harness",       "system-prompts-as-hashes", obs_b6_system_prompts, ["prompt_hashes"]),
    ("agent-v0:C7",  "tool-mcp",      "mcp-server-inventory", obs_c7_mcp_inventory, ["mcp_servers"]),
    ("agent-v0:C8",  "tool-mcp",      "tool-permission-surface", obs_c8_permission_surface, ["harness_permissions", "remote_access"]),
    ("agent-v0:C9",  "tool-mcp",      "identity-credentials-hygiene", obs_c9_identity_credentials, ["ssh_key_inventory", "collector_identity"]),
    ("agent-v0:D10", "containment",   "guardrails-deployed", obs_d10_guardrails, ["guardrail_hooks"]),
    ("agent-v0:D11", "containment",   "isolation-egress-posture", obs_d11_isolation_egress, ["scheduled_execution_surface", "sandbox"]),
    ("agent-v0:E12", "data-memory",   "rag-vector-provenance", obs_e12_rag_provenance, ["memory_corpus_cursor"]),
    ("agent-v0:E13", "data-memory",   "memory-state-pointers", obs_e13_memory_state, ["memory_stores", "retention"]),
    ("agent-v0:F14", "change-time",   "change-events", obs_f14_change_events, ["config_surface_digests"]),
    ("agent-v0:F15", "change-time",   "seal-cadence-records", obs_f15_seal_cadence, ["seal_history", "cadence_policy"]),
    ("agent-v0:G16", "observability", "log-existence-retention-integrity", obs_g16_log_surface, ["log_inventory", "rotation"]),
    ("agent-v0:G17", "observability", "eval-results", obs_g17_eval_results, ["eval_runs"]),
]


# ---------------- state / signing / package assembly ----------------

def state_paths(state_dir):
    sd = H(state_dir)
    return {"dir": sd,
            "state": os.path.join(sd, "state.json"),
            "seal_log": os.path.join(sd, "seal-log.jsonl"),
            "packages": os.path.join(sd, "packages")}


def load_state(paths):
    return load_json(paths["state"]) or {}


def save_state(paths, state):
    os.makedirs(paths["dir"], exist_ok=True)
    with open(paths["state"], "w") as f:
        json.dump(state, f, indent=2)


def keychain_passphrase():
    """Fetch the signing-key passphrase from the macOS login keychain.
    Returns None when unavailable (headless boot, locked keychain): the
    package seals UNSIGNED and says so. Honest degradation, not failure."""
    return run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"], timeout=5)


def can_sign(home):
    if not os.path.isfile(os.path.join(H(home), "identity.key")):
        return False
    if os.environ.get("BEACON_PASSPHRASE"):
        return True
    p = keychain_passphrase()
    if p:
        os.environ["BEACON_PASSPHRASE"] = p
        return True
    return False


def collect_and_seal(reason, changed, paths, home, prev_hash, sequence):
    now = utcnow()
    surfaces = surface_digest()
    fx = {"surfaces": surfaces, "seal_log_path": paths["seal_log"]}

    observations = {}
    items = []
    for slot, layer, name, fn, expected in ELEMENTS:
        try:
            obs = fn(fx)
        except Exception as e:  # an element that errors is recorded, never silently dropped
            obs = {"collection_error": {"present": False, "error": type(e).__name__,
                                        "note": "element collection failed; recorded as failure, not omitted"}}
        observations[slot] = obs

    # one raw blob: the full surface manifests + observations (metadata only)
    seq_label = "seq%04d" % sequence
    pkg_dir = os.path.join(paths["packages"], "%s-%s" % (seq_label, now.replace(":", "").replace("+00.00", "Z")[:15]))
    os.makedirs(pkg_dir, exist_ok=True)
    blob_dir = os.path.join(pkg_dir, "blobs")
    os.makedirs(blob_dir, exist_ok=True)
    raw = {"collected_utc": now, "surfaces": surfaces, "observations": observations}
    raw_bytes = canonical(raw)
    raw_hash = sha256(raw_bytes)
    with open(os.path.join(blob_dir, "sha256-" + raw_hash + ".json"), "wb") as f:
        f.write(raw_bytes)

    provenance = {"box": platform.node(), "access": "local-filesystem",
                  "collector_host": platform.node(), "deployment": "cairn-household"}
    for slot, layer, name, fn, expected in ELEMENTS:
        obs = observations[slot]
        item = {
            "subcriterion": slot,
            "layer": layer,
            "element": name,
            "mode": "agent-continuous",
            "source": {"tool": "beacon-agentmode", "kind": "config-watch", "raw_sha256": raw_hash},
            "provenance": provenance,
            "observation": obs,
            "context": [],
            "completeness": completeness(obs, expected),
            "freshness": {"collected_utc": now, "evidence_age_seconds": 0,
                          "note": "live collection = age 0"},
            "artifact_ref": "blob/sha256-" + raw_hash,
            "collected_utc": now,
        }
        item["item_sha256"] = sha256(canonical(item))
        items.append(item)

    subject = {"name": "cairn-household", "scope": "agentic-deployment:" + platform.node(),
               "collected_utc": now}
    collector = {"name": "beacon-agentmode", "version": VERSION,
                 "platform": platform.system().lower()}
    core = bl.build_package(subject, collector, items)
    core["chain"] = {"sequence": sequence, "prev_package_hash": prev_hash,
                     "reason": reason, "changed_surfaces": changed,
                     "note": "hash chain: anchor any head externally and the whole history is anchored"}

    sign = can_sign(home)
    package = bl.seal_and_sign(core, sign=sign, home=H(home))
    pkg_path = os.path.join(pkg_dir, "package.json")
    with open(pkg_path, "w") as f:
        f.write(json.dumps(package, indent=2))

    entry = {"utc": now, "sequence": sequence, "reason": reason,
             "changed_surfaces": changed, "signed": sign,
             "package_hash": package["seal"]["package_hash"], "path": pkg_path}
    with open(paths["seal_log"], "a") as f:
        f.write(json.dumps(entry) + "\n")

    return package, pkg_path, surfaces


def _trim_own_logs(max_bytes=1_000_000, keep=100_000):
    """Log rotation at birth (house rule): keep the launchd logs bounded."""
    for name in ("launchd.beacon-agent.stdout.log", "launchd.beacon-agent.stderr.log"):
        p = H(os.path.join("~/.claude/CAIRN/logs", name))
        try:
            if os.path.isfile(p) and os.path.getsize(p) > max_bytes:
                with open(p, "rb") as f:
                    f.seek(-keep, 2)
                    tail_bytes = f.read()
                with open(p, "wb") as f:
                    f.write(b"[trimmed by agentmode tick]\n" + tail_bytes)
        except OSError:
            pass


def tick(args):
    _trim_own_logs()
    paths = state_paths(args.state)
    state = load_state(paths)
    now_epoch = time.time()
    current = surface_digest()
    current_digests = {k: v["digest"] for k, v in current.items()}
    prev_digests = state.get("surface_digests")

    if prev_digests is None:
        reason, changed = "initial", sorted(current_digests)
    else:
        changed = sorted(k for k in current_digests
                         if current_digests.get(k) != prev_digests.get(k))
        # surfaces added/removed count as change too
        changed += sorted(set(prev_digests) - set(current_digests))
        if changed:
            reason = "change"
        elif now_epoch - state.get("last_seal_epoch", 0) >= HEARTBEAT_SECONDS:
            reason, changed = "heartbeat", []
        else:
            print("tick: no change, heartbeat not due (%.1fh since last seal)"
                  % ((now_epoch - state.get("last_seal_epoch", 0)) / 3600))
            return

    sequence = state.get("sequence", 0) + 1
    package, pkg_path, surfaces = collect_and_seal(
        reason, changed, paths, args.home, state.get("last_package_hash"), sequence)

    state.update({"surface_digests": {k: v["digest"] for k, v in surfaces.items()},
                  "sequence": sequence,
                  "last_package_hash": package["seal"]["package_hash"],
                  "last_seal_epoch": now_epoch,
                  "last_seal_utc": utcnow(),
                  "last_reason": reason})
    save_state(paths, state)
    signed = package["seal"]["signature"]["alg"] == "ed25519"
    print("sealed %s (seq %d, reason=%s%s, %s) -> %s" % (
        package["seal"]["package_hash"][:16], sequence, reason,
        (", changed: " + ",".join(changed)) if changed and reason == "change" else "",
        "SIGNED" if signed else "unsigned", pkg_path))


def cmd_collect(args):
    paths = state_paths(args.state)
    state = load_state(paths)
    sequence = state.get("sequence", 0) + 1
    package, pkg_path, surfaces = collect_and_seal(
        args.reason, [], paths, args.home, state.get("last_package_hash"), sequence)
    state.update({"surface_digests": {k: v["digest"] for k, v in surfaces.items()},
                  "sequence": sequence,
                  "last_package_hash": package["seal"]["package_hash"],
                  "last_seal_epoch": time.time(), "last_seal_utc": utcnow(),
                  "last_reason": args.reason})
    save_state(paths, state)
    print("sealed -> " + pkg_path)


def _entries_from_packages(paths):
    """Rebuild the chain index from the packages directory itself.

    The seal log is an index, not an authority: it is an append-only convenience
    file that anyone who can write the evidence directory can also edit. Deriving
    the entry list from the sealed packages means an edited or deleted log cannot
    hide a package or invent one.
    """
    entries = []
    for path in sorted(glob.glob(os.path.join(paths["packages"], "*", "package.json"))):
        pkg = load_json(path)
        if pkg is None:
            print("UNREADABLE package at %s" % path)
            continue
        entries.append({"sequence": pkg.get("chain", {}).get("sequence"),
                        "package_hash": pkg.get("seal", {}).get("package_hash"),
                        "path": path})
    entries.sort(key=lambda e: e["sequence"] if e["sequence"] is not None else 0)
    return entries


def verify_chain(args):
    paths = state_paths(args.state)
    entries = _entries_from_packages(paths)
    if not entries:
        sys.exit("no packages under " + paths["packages"])

    # The log is still checked, but as a claim to be reconciled against the
    # packages, never as the source of truth.
    if os.path.isfile(paths["seal_log"]):
        with open(paths["seal_log"]) as f:
            logged = [json.loads(line) for line in f if line.strip()]
        on_disk = {e["sequence"] for e in entries}
        in_log = {e.get("sequence") for e in logged}
        if in_log - on_disk:
            print("LOG CLAIMS MISSING PACKAGES: seq %s"
                  % ", ".join(str(s) for s in sorted(in_log - on_disk)))
        if on_disk - in_log:
            print("PACKAGES ABSENT FROM LOG: seq %s (log edited, or written out of band)"
                  % ", ".join(str(s) for s in sorted(on_disk - in_log)))
    else:
        print("NOTE: no seal log present; verifying from packages alone")

    ok = True
    inconclusive = False
    prev_hash = None
    prev_seq = 0
    for e in entries:
        pkg = load_json(e["path"])
        if pkg is None:
            print("MISSING package seq %d at %s" % (e["sequence"], e["path"]))
            ok = False
            prev_hash, prev_seq = e["package_hash"], e["sequence"]
            continue
        chain = pkg.get("chain", {})
        if chain.get("prev_package_hash") != prev_hash:
            print("CHAIN BREAK at seq %d: prev_package_hash mismatch" % e["sequence"])
            ok = False
        if chain.get("sequence") != prev_seq + 1:
            print("CHAIN BREAK at seq %d: sequence gap (expected %d)" % (e["sequence"], prev_seq + 1))
            ok = False
        blob_dir = os.path.join(os.path.dirname(e["path"]), "blobs")
        if not bl.verify_package(pkg, blob_dir=blob_dir,
                                 registry=os.path.join(H(args.home), "registry-stub")):
            if bl.HAVE_CRYPTO or os.environ.get("BEACON_ALLOW_UNVERIFIED") == "1":
                ok = False
            else:
                inconclusive = True
        prev_hash, prev_seq = e["package_hash"], e["sequence"]
    if not ok:
        verdict = "BROKEN"
    elif inconclusive:
        verdict = "UNPROVEN (hashes intact, signatures uncheckable here)"
    else:
        verdict = "INTACT"
    print("\nCHAIN %s: %d packages, head %s" % (
        verdict, len(entries), prev_hash[:16] if prev_hash else "none"))
    sys.exit(0 if (ok and not inconclusive) else 1)


def status(args):
    paths = state_paths(args.state)
    state = load_state(paths)
    if not state:
        print("no state at %s (never ticked)" % paths["state"])
        return
    print("beacon agentmode %s" % VERSION)
    print("  sequence:      %s" % state.get("sequence"))
    print("  last seal:     %s (%s)" % (state.get("last_seal_utc"), state.get("last_reason")))
    print("  chain head:    %s" % (state.get("last_package_hash") or "")[:16])
    print("  heartbeat:     every %dh" % (HEARTBEAT_SECONDS // 3600))
    print("  signing:       %s" % ("available" if can_sign(args.home) else "UNAVAILABLE (will seal unsigned)"))
    print("  watched:       %s" % ", ".join(sorted(WATCHED_SURFACES)))


def cmd_diff(args):
    import beacondiff as bd
    packages = bd.load_packages(args.state)
    seqs = bd.by_sequence(packages)
    if not seqs:
        sys.exit("no packages under %s" % args.state)
    lo = args.from_seq if args.from_seq is not None else max(seqs) - 1
    hi = args.to_seq if args.to_seq is not None else max(seqs)
    for s in (lo, hi):
        if s not in seqs:
            sys.exit("no package at sequence %s (have %s..%s)" % (s, min(seqs), max(seqs)))
    doc = bd.diff_packages(seqs[lo], seqs[hi], include_noise=args.include_noise)
    print(json.dumps(doc, indent=2) if args.format == "json" else bd.render_text(doc))


def cmd_timeline(args):
    import beacondiff as bd
    packages = bd.load_packages(args.state)
    if not packages:
        sys.exit("no packages under %s" % args.state)
    doc = bd.build_timeline(packages, include_noise=args.include_noise)
    if args.html:
        out = os.path.abspath(os.path.expanduser(args.html))
        with open(out, "w") as f:
            f.write(bd.render_html(doc, packages))
        print("wrote %s (%d packages, %d change events)"
              % (out, doc["package_count"], len([e for e in doc["events"] if e["changed_elements"]])))
        return
    print(json.dumps(doc, indent=2) if args.format == "json" else bd.render_text(doc))


def cmd_anchor(args):
    """Publish unanchored packages to multiple independent trust domains.

    Runs asynchronously and out of band from sealing on purpose: an anchor
    service being down must never stop the collector from recording evidence.
    """
    import anchors as an
    import beacondiff as bd

    packages = [p for p in bd.load_packages(args.state) if "_load_error" not in p]
    if not packages:
        sys.exit("no packages under %s" % args.state)

    epoch_dir = os.path.join(H(args.state), "anchors")
    os.makedirs(epoch_dir, exist_ok=True)

    # Single-writer lock. The hourly job can overlap a long manual run, and two
    # concurrent runs would both mint the same epoch number and clobber each
    # other's queue write. Anchoring is idempotent across runs but not across
    # simultaneous ones.
    lock_path = os.path.join(epoch_dir, ".anchor.lock")
    lock = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        print("another anchor run holds the lock; skipping this pass")
        return

    # --- per-package RFC 3161, the cheap synchronous anchor -------------
    late = 0
    for pkg in packages:
        pkg_path = pkg["_path"]
        tsr_path = pkg_path + ".tsr"
        rec_path = pkg_path + ".anchors.json"
        if os.path.isfile(tsr_path):
            continue
        sealed_at = pkg.get("subject", {}).get("collected_utc")
        token, meta = an.rfc3161_anchor_file(pkg_path, sealed_at)
        if token is None:
            print("  tsa failed for seq %s: %s" % (pkg["chain"]["sequence"], meta.get("error", "")[:80]))
            continue
        if meta.get("late_anchor"):
            late += 1
        rec = load_json(rec_path) or {"package_hash": pkg["seal"]["package_hash"], "anchors": []}
        rec["anchors"] = [a for a in rec["anchors"] if a.get("kind") != "rfc3161"] + [meta]
        with open(rec_path, "w") as f:
            json.dump(rec, f, indent=2)
    if late:
        print("note: %d package(s) timestamped late; recorded as late_anchor, not backdated" % late)

    # --- epoch batching for the expensive anchors -----------------------
    q = an.load_queue()
    already = set()
    for ep in q["epochs"].values():
        already.update(ep.get("sequences", []))
    fresh = [p for p in packages if p["chain"]["sequence"] not in already]
    if not fresh and args.skip_empty:
        print("no packages awaiting epoch anchoring (empty epoch skipped by request)")
    else:
        prev_id = max([int(k) for k in q["epochs"]] or [0])
        epoch_id = str(prev_id + 1)
        prev_root = (q["epochs"].get(str(prev_id)) or {}).get("anchored_root", "")

        hashes = [bytes.fromhex(p["seal"]["package_hash"]) for p in fresh]
        tree_root, paths = an.merkle_root_and_paths(hashes)
        seqs = [p["chain"]["sequence"] for p in fresh]

        # The anchored value commits to the epoch number, its tree, AND the
        # previous epoch's anchored root. That chains the epochs to each other,
        # so removing one does not merely leave a numeric gap, it breaks the
        # epoch chain. Empty epochs are anchored too: a continuous heartbeat
        # means silence is unambiguous rather than deniable.
        root = an.epoch_commitment(epoch_id, tree_root, prev_root)

        root_file = os.path.join(epoch_dir, "epoch-%s.root" % epoch_id)
        with open(root_file, "wb") as f:
            f.write(root)

        entry = {"epoch": epoch_id, "created_utc": an.utcnow(), "sequences": seqs,
                 "tree_size": len(hashes),
                 "tree_root": tree_root.hex() if tree_root else None,
                 "prev_epoch_anchored_root": prev_root or None,
                 "anchored_root": root.hex(),
                 "empty": not fresh,
                 "anchors": [], "attempts": 0}

        proof, ots_meta = an.ots_stamp(root_file)
        entry["anchors"].append(ots_meta)

        sig_b, pub_der = _sign_root(root, args.home)
        if sig_b is None:
            entry["anchors"].append({"kind": "rekor-v2", "state": "pending",
                                     "reason": "signing key unavailable"})
        else:
            resp, rk_meta = an.rekor_submit(root, sig_b, pub_der)
            entry["anchors"].append(rk_meta)
            if resp is not None:
                with open(os.path.join(epoch_dir, "epoch-%s.rekor.json" % epoch_id), "w") as f:
                    json.dump(resp, f, indent=2)

        # inclusion path per package, so a single seal proves out to the root
        for i, p in enumerate(fresh):
            rec_path = p["_path"] + ".anchors.json"
            rec = load_json(rec_path) or {"package_hash": p["seal"]["package_hash"], "anchors": []}
            rec["merkle"] = {"epoch": epoch_id, "leaf_index": i, "tree_size": len(hashes),
                             "root": tree_root.hex(), "path": paths[i],
                             "epoch_anchored_root": root.hex()}
            with open(rec_path, "w") as f:
                json.dump(rec, f, indent=2)

        q["epochs"][epoch_id] = entry
        an.save_queue(q)
        print("epoch %s: %d package(s)%s, anchored root %s"
              % (epoch_id, len(hashes), " (EMPTY heartbeat)" if not fresh else "",
                 root.hex()[:16]))
        for a in entry["anchors"]:
            print("  %-14s %s%s" % (a["kind"], a["state"],
                                    (" (%s)" % a.get("substate")) if a.get("substate") else ""))

    if args.upgrade:
        # Re-stamp first: an epoch whose proof never got created has nothing for
        # the upgrade pass to work on, and it is the case the upgrade pass is
        # structurally blind to.
        cmd_anchor_restamp(args)
        cmd_anchor_upgrade(args)


def _sign_root(root, home):
    # can_sign() resolves the passphrase from the keychain into the environment
    # and returns False when it cannot. Without this gate, load_private_key()
    # falls through to an interactive prompt, which in a launchd or background
    # run blocks forever instead of degrading. An anchor step must never be able
    # to hang the collector: unsigned-and-honest beats stuck.
    if not can_sign(home):
        return None, None
    try:
        import enroll
        priv = enroll.load_private_key(H(home))
        from cryptography.hazmat.primitives import serialization
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return priv.sign(root), pub_der
    except SystemExit:
        return None, None
    except Exception:
        return None, None


def _iso_to_epoch(ts, fallback):
    """ISO-8601 to unix seconds, tolerant: a malformed stamp must not decide policy."""
    if not ts:
        return fallback
    try:
        import datetime
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return fallback


def cmd_anchor_restamp(args):
    """Re-submit epochs whose OTS stamp never produced a proof file at all.

    ots_stamp() records state="pending" with an error and NO artifact when the
    calendars refuse. That happened twice: 2026-08-27 (epoch 52) and 2026-08-30
    (epoch 126), both "Failed to create timestamp: need at least 2 attest", a
    transient calendar-pool outage.

    cmd_anchor_upgrade skips those epochs, correctly, because there is no .ots
    file to upgrade. But nothing else touched them either, so a momentary outage
    orphaned an epoch permanently. Epoch 52 sat pending for three days while the
    liveness watcher reported it as awaiting a Bitcoin block and pointed the
    reader at the upgrade job, a remedy aimed at a subsystem that could not
    possibly help.

    anchors.due() already implements exponential backoff with a hard abandon
    horizon, and had no caller anywhere in the tree. This is that caller.

    On crossing the abandon horizon the anchor is marked failed rather than left
    pending, because the watcher has an ANCHORFAILED finding and no way at all to
    see a silence. Written 2026-08-30.
    """
    import anchors as an
    q = an.load_queue()
    now = time.time()
    anchor_dir = os.path.join(H(args.state), "anchors")
    changed = restamped = abandoned = 0

    for eid, ep in sorted(q["epochs"].items(), key=lambda kv: int(kv[0])):
        for a in ep.get("anchors", []):
            if a.get("kind") != "opentimestamps":
                continue
            if a.get("state") in ("confirmed", "submitted", "failed"):
                continue

            root_file = os.path.join(anchor_dir, "epoch-%s.root" % eid)
            if os.path.isfile(root_file + ".ots"):
                continue          # a proof exists; the upgrade pass owns it
            if not os.path.isfile(root_file):
                continue          # nothing to stamp: a different, louder problem

            # Measure the abandon horizon from the FIRST attempt. Seeding it from
            # now on every pass would reset the clock and retry forever.
            if not ep.get("first_attempt_epoch"):
                ep["first_attempt_epoch"] = _iso_to_epoch(
                    a.get("first_submitted") or a.get("submitted"), now)

            if now - ep["first_attempt_epoch"] > an.ABANDON_AFTER_SECONDS:
                a["state"] = "failed"
                a["abandoned"] = an.utcnow()
                a["abandon_reason"] = (
                    "no OTS proof after %d days of retries; this epoch is chained "
                    "locally but has no external Bitcoin attestation"
                    % (an.ABANDON_AFTER_SECONDS // 86400))
                abandoned += 1
                changed += 1
                print("epoch %s ots: ABANDONED after %d days"
                      % (eid, an.ABANDON_AFTER_SECONDS // 86400))
                continue

            if not an.due(ep, now):
                continue

            # Preserve the original submission time: overwriting it with each
            # retry would erase how long this epoch has actually been unproven.
            if not a.get("first_submitted"):
                a["first_submitted"] = a.get("submitted")

            try:
                proof, meta = an.ots_stamp(root_file)
            except Exception as e:
                # One wedged epoch must not stop the pass for the others.
                ep["attempts"] = ep.get("attempts", 0) + 1
                ep["last_attempt_epoch"] = now
                a["error"] = "ots stamp raised %s" % type(e).__name__
                changed += 1
                print("epoch %s ots: re-stamp raised %s" % (eid, type(e).__name__))
                continue

            first_sub = a.get("first_submitted")
            a.update(meta)
            a["first_submitted"] = first_sub
            ep["attempts"] = ep.get("attempts", 0) + 1
            ep["last_attempt_epoch"] = now
            changed += 1
            if proof:
                restamped += 1
                print("epoch %s ots: re-stamped on attempt %d -> %s"
                      % (eid, ep["attempts"], a["state"]))
            else:
                tail = (a.get("error") or "").strip().splitlines()[-1:] or [""]
                print("epoch %s ots: re-stamp attempt %d failed (%s)"
                      % (eid, ep["attempts"], tail[0]))

    if changed:
        an.save_queue(q)
    print("restamp pass: %d re-stamped, %d abandoned, %d record(s) updated"
          % (restamped, abandoned, changed))


def cmd_anchor_upgrade(args):
    """Pull completed Bitcoin paths down. Until this runs, OTS proofs are not
    self-contained and depend on calendar servers still existing."""
    import anchors as an
    q = an.load_queue()
    changed = 0
    for eid, ep in sorted(q["epochs"].items(), key=lambda kv: int(kv[0])):
        for a in ep.get("anchors", []):
            if a.get("kind") != "opentimestamps" or a.get("state") == "confirmed":
                continue
            proof = os.path.join(H(args.state), "anchors", "epoch-%s.root.ots" % eid)
            if not os.path.isfile(proof):
                continue
            ok, meta = an.ots_upgrade(proof)
            a.update(meta)
            changed += 1
            print("epoch %s ots: %s%s" % (eid, a["state"],
                  (" block %s" % a.get("bitcoin_block")) if ok else " (not yet in a block)"))
    if changed:
        an.save_queue(q)
    elif not q["epochs"]:
        print("no epochs to upgrade")


def cmd_verify_anchors(args):
    """Offline verification, the way a third party would do it months later."""
    import anchors as an
    import beacondiff as bd
    packages = [p for p in bd.load_packages(args.state) if "_load_error" not in p]
    ok = True
    counts = {"rfc3161": 0, "merkle": 0, "missing": 0}
    for pkg in packages:
        seq = pkg["chain"]["sequence"]
        rec = load_json(pkg["_path"] + ".anchors.json")
        if not rec:
            counts["missing"] += 1
            continue

        m = rec.get("merkle")
        if m:
            good = an.verify_path(bytes.fromhex(rec["package_hash"]), m["path"],
                                  bytes.fromhex(m["root"]))
            counts["merkle"] += 1 if good else 0
            if not good:
                print("seq %s: MERKLE PATH INVALID" % seq)
                ok = False

        tsr = pkg["_path"] + ".tsr"
        if os.path.isfile(tsr):
            r = subprocess.run(
                ["openssl", "ts", "-verify", "-in", tsr, "-data", pkg["_path"],
                 "-CAfile", os.path.join(an.TRUST_DIR, "freetsa-cacert.pem"),
                 "-untrusted", os.path.join(an.TRUST_DIR, "freetsa-tsa.crt")],
                capture_output=True, text=True)
            if "Verification: OK" in (r.stdout + r.stderr):
                counts["rfc3161"] += 1
            else:
                print("seq %s: TSA TOKEN FAILED VERIFICATION" % seq)
                ok = False

    print("\nANCHORS %s: %d rfc3161 tokens verified offline, %d merkle paths valid, "
          "%d package(s) with no anchor record"
          % ("OK" if ok else "PROBLEM", counts["rfc3161"], counts["merkle"], counts["missing"]))

    q = an.load_queue()
    for eid, ep in sorted(q["epochs"].items(), key=lambda kv: int(kv[0])):
        states = ", ".join("%s=%s" % (a["kind"], a["state"]) for a in ep.get("anchors", []))
        print("  epoch %s: %d packages, %s" % (eid, ep["tree_size"], states))
    if not an.rekor_enabled():
        print("\n  rekor publication is OFF (permanent public log; enable deliberately by\n"
              "  creating %s)" % an.REKOR_ENABLED_FLAG)
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--home", default=DEFAULT_HOME)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tick")
    c = sub.add_parser("collect")
    c.add_argument("--reason", default="manual")
    sub.add_parser("verify-chain")
    sub.add_parser("status")

    d = sub.add_parser("diff", help="diff two sealed packages")
    d.add_argument("--from", dest="from_seq", type=int, default=None)
    d.add_argument("--to", dest="to_seq", type=int, default=None)
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("--include-noise", action="store_true",
                   help="include per-seal bookkeeping fields (timestamps, blob refs)")

    t = sub.add_parser("timeline", help="assembled change timeline across the chain")
    t.add_argument("--format", choices=["text", "json"], default="text")
    t.add_argument("--html", default=None, metavar="PATH", help="write the visual change ribbon")
    t.add_argument("--include-noise", action="store_true")

    a = sub.add_parser("anchor", help="publish unanchored packages to the anchor set")
    a.add_argument("--upgrade", action="store_true",
                   help="also run the OTS upgrade pass afterwards")
    a.add_argument("--skip-empty", action="store_true",
                   help="do not emit an epoch when nothing new sealed (breaks the "
                        "heartbeat property; only for manual runs)")
    up = sub.add_parser("anchor-upgrade", help="pull completed Bitcoin paths down")
    sub.add_parser("anchor-restamp",
                   help="re-submit epochs whose OTS stamp never produced a proof")
    sub.add_parser("verify-anchors", help="offline verification of every stored anchor")

    args = ap.parse_args()
    {"tick": tick, "collect": cmd_collect, "verify-chain": verify_chain,
     "status": status, "diff": cmd_diff, "timeline": cmd_timeline,
     "anchor": cmd_anchor, "anchor-upgrade": cmd_anchor_upgrade,
     "anchor-restamp": cmd_anchor_restamp,
     "verify-anchors": cmd_verify_anchors}[args.cmd](args)


if __name__ == "__main__":
    main()
