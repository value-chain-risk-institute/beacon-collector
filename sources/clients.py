"""
clients.py: MCP configuration across agent clients (extends C7) and local model
runtimes (Ollama, extends A1/A2).

MCP: reads each known client's config file and records, per server, the transport,
the command's basename and file hash when it is a local file, a commitment-free
hash of its arguments, env KEY NAMES only (never values, they are often tokens),
and for remote servers the scheme and host only (URLs can carry tokens in the
query). stdio servers are never executed to list their tools: reading a tool list
from a stdio server means running it.

Ollama: /api/ps names the models loaded right now and the DIGEST of their weights.
That digest is an observation of what is loaded, the only true served-artifact
identity available for any model in this research; hosted APIs only give a label.
"""
import hashlib
import json
import os
import tomllib
import urllib.parse
import urllib.request

H = os.path.expanduser

CLIENT_CONFIGS = [
    ("claude-code-user", "~/.claude.json", "json", "mcpServers"),
    ("claude-code-household", "~/.claude/.mcp.json", "json", "mcpServers"),
    ("claude-desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "json", "mcpServers"),
    ("cursor", "~/.cursor/mcp.json", "json", "mcpServers"),
    ("windsurf", "~/.codeium/windsurf/mcp_config.json", "json", "mcpServers"),
    ("gemini-cli", "~/.gemini/settings.json", "json", "mcpServers"),
    ("codex", "~/.codex/config.toml", "toml", "mcp_servers"),
    ("vscode-user", "~/Library/Application Support/Code/User/mcp.json", "json", "servers"),
    ("kiro", "~/.kiro/settings/mcp.json", "json", "mcpServers"),
    ("cline", "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "json", "mcpServers"),
]


def _sha_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _sha_obj(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


def _server_entry(name, cfg):
    e = {"name": name}
    url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl")
    if url:
        u = urllib.parse.urlsplit(str(url))
        e["transport"] = cfg.get("type") or "remote"
        e["remote"] = {"scheme": u.scheme, "host": u.hostname, "port": u.port}
    else:
        cmd = cfg.get("command")
        e["transport"] = cfg.get("type") or "stdio"
        if cmd:
            e["command_basename"] = os.path.basename(str(cmd))
            if os.path.isfile(H(str(cmd))):
                e["command_sha256"] = _sha_file(H(str(cmd)))
        args = cfg.get("args") or []
        e["args_sha256"] = _sha_obj(args)
        e["args_count"] = len(args)
        for a in args:
            if isinstance(a, str) and os.path.isfile(H(a)):
                e["server_file_sha256"] = _sha_file(H(a))
                break
    env = cfg.get("env") or {}
    if isinstance(env, dict) and env:
        e["env_keys"] = sorted(env)
    if cfg.get("disabled") is not None:
        e["disabled"] = bool(cfg.get("disabled"))
    return e


def _servers_from(doc, key):
    out = []
    block = doc.get(key) if isinstance(doc, dict) else None
    if isinstance(block, dict):
        out += [_server_entry(n, c) for n, c in sorted(block.items()) if isinstance(c, dict)]
    # Claude Code keeps per-project servers inside ~/.claude.json under projects.<path>
    projects = doc.get("projects") if isinstance(doc, dict) else None
    if key == "mcpServers" and isinstance(projects, dict):
        for p, pc in sorted(projects.items()):
            block = pc.get("mcpServers") if isinstance(pc, dict) else None
            if isinstance(block, dict):
                for n, c in sorted(block.items()):
                    if isinstance(c, dict):
                        e = _server_entry(n, c)
                        e["scope"] = "project:" + hashlib.sha256(p.encode()).hexdigest()[:12]
                        out.append(e)
    return out


def mcp_clients(configs=CLIENT_CONFIGS):
    clients = []
    for client, path, fmt, key in configs:
        p = H(path)
        if not os.path.isfile(p):
            clients.append({"client": client, "config": path, "present": False})
            continue
        entry = {"client": client, "config": path, "present": True}
        try:
            if fmt == "toml":
                with open(p, "rb") as f:
                    doc = tomllib.load(f)
            else:
                with open(p) as f:
                    doc = json.load(f)
            servers = _servers_from(doc, key)
            entry.update({"servers": servers, "server_count": len(servers),
                          # the hash of the MCP-relevant block only: ~/.claude.json
                          # also holds churning UI state that is not configuration
                          "mcp_block_sha256": _sha_obj(servers)})
        except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
            entry.update({"parse_error": type(e).__name__})
        clients.append(entry)
    return clients


def ollama(base="http://127.0.0.1:11434", timeout=1.0):
    def get(path):
        with urllib.request.urlopen(base + path, timeout=timeout) as r:
            return json.loads(r.read().decode())
    try:
        ps = get("/api/ps")
        tags = get("/api/tags")
    except Exception as e:
        return {"present": False, "endpoint": base, "error": type(e).__name__,
                "note": "no local Ollama answering here; absence recorded"}
    loaded = [{"name": m.get("name"), "digest": m.get("digest"),
               "size_vram": m.get("size_vram"), "expires_at": m.get("expires_at")}
              for m in ps.get("models", [])]
    installed = [{"name": m.get("name"), "digest": m.get("digest"),
                  "modified_at": m.get("modified_at")} for m in tags.get("models", [])]
    return {"present": True, "endpoint": base, "loaded": loaded, "installed": installed,
            "grade": "observed: weights digest of what is loaded, not a label"}
