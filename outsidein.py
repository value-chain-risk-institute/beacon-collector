#!/usr/bin/env python3
"""
outsidein.py, Beacon Collector adapter: outside-in checks of ONE domain the operator names.

What it does, and all it does: two DNS TXT lookups (SPF at the domain, DMARC at
_dmarc.<domain>) and one TLS handshake to <domain>:443. No port scan, no crawl, no
third-party rating service, no domain discovery. It exists so an organization can
seal what the public internet sees of its own mail and web front door beside its
inside evidence. It is the org's self-check, not BitSight-style scanning of others
(SPEC non-goal), and the operator is responsible for naming only a domain it owns.

Epistemic class: the collector itself made these observations from outside, live,
so items are epistemic="observed_scan", mode="scanner", with
provenance.access="external-vantage" and source.kind="outside_in" so no one mistakes
an outside view for an inside one.

Slots: TLS -> data-v1:in-transit. SPF/DMARC -> "unmapped" (no rubric home for email
domain authentication; see ADAPTER-ROADMAP.md gaps).

  outsidein.py collect --domain example.org [--resolver 1.1.1.1] [--subject NAME]
  outsidein.py verify out-outside-in/package.json

DNS is a ~40-line stdlib client (no dnspython); certificate parsing uses the
`cryptography` library the collector already depends on.
"""
import argparse
import base64
import json
import os
import random
import socket
import ssl
import struct
import sys
from datetime import datetime, timezone

import adapterkit as ak
import beaconlib as bl


# ---------------- DNS (TXT only) ----------------

def build_query(name, qid, qtype=16):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode("idna")
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(buf, off):
    while True:
        n = buf[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += n + 1


def parse_txt_response(buf, qid):
    rid, flags, qd, an = struct.unpack(">HHHH", buf[:8])
    if rid != qid:
        raise ValueError("DNS response id mismatch")
    rcode = flags & 0xF
    if rcode == 3:
        return {"rcode": "NXDOMAIN", "txt": [], "truncated": False}
    if rcode != 0:
        raise ValueError("DNS rcode %d" % rcode)
    off = 12
    for _ in range(qd):
        off = _skip_name(buf, off) + 4
    txt = []
    for _ in range(an):
        off = _skip_name(buf, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        off += rdlen
        if rtype == 16:
            parts, i = [], 0
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            txt.append("".join(parts))
    return {"rcode": "NOERROR", "txt": txt, "truncated": bool(flags & 0x0200)}


def system_resolver():
    try:
        for line in open("/etc/resolv.conf"):
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver" and ":" not in f[1]:
                return f[1]
    except OSError:
        pass
    return None


def query_txt(name, resolver, timeout=5.0):
    qid = random.randint(0, 0xFFFF)
    q = build_query(name, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (resolver, 53))
        buf = s.recv(4096)
    res = parse_txt_response(buf, qid)
    if res["truncated"]:
        with socket.create_connection((resolver, 53), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(q)) + q)
            ln = struct.unpack(">H", s.recv(2))[0]
            data = b""
            while len(data) < ln:
                data += s.recv(ln - len(data))
        res = parse_txt_response(data, qid)
    return res


# ---------------- facts (no judgment) ----------------

def spf_facts(txt):
    recs = [t for t in txt if t.lower().startswith("v=spf1")]
    all_q = None
    if len(recs) == 1:
        for term in recs[0].split()[1:]:
            if term.lower().lstrip("+-~?") == "all":
                all_q = term if term[0] in "+-~?" else "+" + term
    return {"present": bool(recs), "record_count": len(recs), "records": recs,
            "all_mechanism": all_q,
            "note": "RFC 7208: more than one v=spf1 record is a permerror; recorded as a count, not judged"}


def dmarc_facts(txt):
    recs = [t for t in txt if t.replace(" ", "").lower().startswith("v=dmarc1")]
    tags = {}
    if len(recs) == 1:
        for part in recs[0].split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
    return {"present": bool(recs), "record_count": len(recs), "records": recs,
            "policy": tags.get("p"), "subdomain_policy": tags.get("sp"), "pct": tags.get("pct"),
            "aggregate_reporting": "rua" in tags}


def describe_cert(der, now=None):
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.now(timezone.utc)
    na = cert.not_valid_after_utc
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(), "not_after": na.isoformat(),
            "days_until_expiry": (na - now).days, "san_dns_names": sorted(sans)[:50],
            "san_count": len(sans), "sha256_fingerprint": bl.sha256(der)}


def tls_facts(host, port=443, timeout=10.0):
    out = {"present": False, "host": host, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                out.update(present=True, chain_valid_and_hostname_match=True,
                           negotiated_protocol=s.version(), cipher=s.cipher()[0])
    except ssl.SSLCertVerificationError as e:
        out.update(chain_valid_and_hostname_match=False, verify_error=e.verify_message or str(e))
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                out.update(present=True, negotiated_protocol=s.version(), cipher=s.cipher()[0])
    except (OSError, ssl.SSLError) as e:
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
        return out, None
    out["certificate"] = describe_cert(der)
    return out, der


def observe(domain, txt_lookup, tls_probe):
    """Pure assembly; the two probes are injected so tests run offline."""
    spf_raw = txt_lookup(domain)
    dmarc_raw = txt_lookup("_dmarc." + domain)
    tls, der = tls_probe(domain)
    raw = {"domain": domain, "dns": {domain: spf_raw, "_dmarc." + domain: dmarc_raw},
           "tls": tls, "certificate_der_b64": base64.b64encode(der).decode() if der else None}
    return {"spf": spf_facts(spf_raw["txt"]), "dmarc": dmarc_facts(dmarc_raw["txt"])}, tls, raw


def build_items(domain, email, tls, raw_hash, now, box):
    src = {"tool": "beacon-outside-in", "kind": "outside_in", "domain": domain}
    prov = {"box": box or ("external:" + domain), "access": "external-vantage",
            "note": "observed from the public internet, not from inside the organization"}
    fresh = ak.freshness(now, note="live outside-in check", live=True)
    return [
        ak.make_item("data-v1:in-transit", "scanner", "observed_scan", True, src, prov, "tls", tls,
                     raw_hash, now, fresh, ak.mapped("outsidein: TLS on <domain>:443")),
        ak.make_item(ak.UNMAPPED, "scanner", "observed_scan", True, src, prov, "email_domain_auth",
                     {"present": True, **email}, raw_hash, now, fresh,
                     ak.unmapped("no rubric subcriterion for email domain authentication (SPF/DMARC)",
                                 ["technology-v1/4c", "people-v1/4c"])),
    ]


def collect(args):
    domain = args.domain.strip().lower().rstrip(".")
    resolver = args.resolver or system_resolver()
    if not resolver:
        sys.exit("no IPv4 resolver found in /etc/resolv.conf; pass --resolver")
    try:
        email, tls, raw = observe(domain, lambda n: query_txt(n, resolver), tls_facts)
    except (OSError, ValueError) as e:
        sys.exit("outside-in check failed (%s); no package written" % e)
    raw["resolver"] = resolver
    now = bl.utcnow()
    os.makedirs(args.out_dir, exist_ok=True)
    raw_hash = ak.write_blob(args.out_dir, bl.canonical(raw))
    items = build_items(domain, email, tls, raw_hash, now, args.box)
    subject = {"name": args.subject or domain, "scope": "outside-in:" + domain, "collected_utc": now}
    collector = {"name": "beacon-outside-in", "version": "0.1.0", "platform": "any"}
    package, out_path = ak.seal_write(args, items, subject, collector)
    c = tls.get("certificate") or {}
    print("outside-in %s via resolver %s" % (domain, resolver))
    print("  SPF records %d (all=%s) | DMARC records %d (p=%s) | TLS %s, cert expires %s (%s days)" % (
        email["spf"]["record_count"], email["spf"]["all_mechanism"], email["dmarc"]["record_count"],
        email["dmarc"]["policy"], tls.get("negotiated_protocol") or tls.get("error"),
        c.get("not_after"), c.get("days_until_expiry")))
    ak.summarize(items, package, out_path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--domain", required=True, help="a domain your organization owns")
    c.add_argument("--resolver", help="IPv4 DNS resolver (default: first in /etc/resolv.conf)")
    ak.add_common(c, "out-outside-in")
    ak.add_verify(sub)
    a = ap.parse_args()
    (collect if a.cmd == "collect" else ak.cmd_verify)(a)
