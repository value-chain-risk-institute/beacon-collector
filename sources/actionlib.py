"""
actionlib.py: shared pieces for the H layer (agent actions), v0.3.

One record shape for every side (claim, vendor, observed), so pairing is a join,
not an interpretation. Content never enters a record in clear. Prompts, tool
inputs and outputs, commands and paths become per-item commitments
sha256(nonce || value), where each item's nonce is derived from a per-deployment
key the org holds. A plain SHA-256 of a short command or path is recoverable by
guessing; this is not. And the org can open ONE item for an examiner by handing
over that item's nonce and bytes, without the key and without opening any other.
Identifiers (session ids, file paths of transcripts) become keyed pseudonyms.

Deliberately standard library only, and small: the Claude Code hook imports this
on every tool call, so it must load fast and must never raise into the agent.
"""
import hashlib
import hmac
import json
import os
import secrets

ACTION_SCHEMA = "beacon-agent-action/v0"
KEY_NAME = "commit.key"

# Vendor correlation ids and plain metadata stay in clear: they are not content,
# and they are what lets an examiner line our record up against the vendor's.
CLEAR_FIELDS = (
    "hook_event_name", "tool_name", "tool_use_id", "permission_mode", "source",
    "model", "agent_id", "agent_type", "stop_hook_active", "trigger", "reason",
    "matcher", "notification_type", "is_interrupt", "prompt_id", "duration_ms",
)
# Everything that can carry content or identify a place on disk is committed.
COMMIT_FIELDS = (
    "prompt", "tool_input", "tool_response", "error", "message", "cwd",
    "transcript_path", "custom_instructions", "last_assistant_message",
)


def actions_dir(state_dir):
    d = os.path.join(os.path.expanduser(state_dir), "actions")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def load_key(state_dir, create=True):
    """Per-deployment commitment key. Created once with O_EXCL so two hooks racing
    at first use cannot each write a different key."""
    path = os.path.join(actions_dir(state_dir), KEY_NAME)
    try:
        with open(path, "rb") as f:
            k = f.read()
        if len(k) == 32:
            return k
    except FileNotFoundError:
        if not create:
            return None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    with open(path, "rb") as f:
        return f.read()


def key_id(key):
    """Public, non-secret label for which key made a commitment."""
    return hashlib.sha256(b"beacon-commit-key-id:" + key).hexdigest()[:16]


def _bytes(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def ref(key, value):
    """Keyed pseudonym for an identifier (session id, transcript path): stable, so
    records join on it, and unlinkable to the identifier without the key."""
    b = _bytes(value)
    if b is None:
        return None
    return "ref:" + hmac.new(key, b, hashlib.sha256).hexdigest()


def nonce(key, scope):
    """Per-item opening secret, derived from the deployment key and the item's scope
    (for example 'tool_input:<tool_use_id>'). Disclosing one nonce opens one item and
    reveals nothing about the key or any other item."""
    return hmac.new(key, b"beacon-nonce\0" + scope.encode(), hashlib.sha256).digest()


def commit(key, value, scope):
    """'c1:<hex>' = sha256(nonce(scope) || value). Hiding: a guessable command or path
    cannot be confirmed without the nonce. Binding: SHA-256. Two sources that see the
    same value under the same scope (the hook and the transcript, joined on
    tool_use_id) produce the same commitment, so pairing still works on commitments."""
    b = _bytes(value)
    if b is None:
        return None
    return "c1:" + hashlib.sha256(nonce(key, scope) + b).hexdigest()


def opening(key, value, scope):
    """What the org hands a verifier to prove ONE item: scope, nonce, exact bytes."""
    import base64
    return {"scope": scope, "nonce_hex": nonce(key, scope).hex(),
            "value_b64": base64.b64encode(_bytes(value)).decode()}


def check_opening(commitment, op):
    """Verifier side: no key needed."""
    import base64
    b = base64.b64decode(op["value_b64"])
    return commitment == "c1:" + hashlib.sha256(bytes.fromhex(op["nonce_hex"]) + b).hexdigest()


def size(value):
    b = _bytes(value)
    return len(b) if b is not None else None


def record(side, source, event, ts_utc, ts_source, **kw):
    """Normalized action record. Unknown keyword fields are an error in tests, not
    silently stored: the shape is the contract."""
    r = {"schema": ACTION_SCHEMA, "side": side, "source": source, "event": event,
         "ts_utc": ts_utc, "ts_source": ts_source,
         "agent": kw.pop("agent", {}), "correlation": kw.pop("correlation", {}),
         "model": kw.pop("model", {}), "tool": kw.pop("tool", {}),
         "content_commitments": kw.pop("content_commitments", {}),
         "sizes": kw.pop("sizes", {}), "content_ref": None}
    if kw:
        raise TypeError("unknown action record fields: %s" % sorted(kw))
    return r


def line_hash(prev_hash, line_bytes):
    """Per-file hash chain over spool lines: h_n = sha256(h_{n-1} || line_n)."""
    return hashlib.sha256((prev_hash or "genesis").encode() + b"\n" + line_bytes).hexdigest()
