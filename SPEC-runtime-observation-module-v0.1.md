# Spec item: runtime observation module ("the kernel keeps receipts")

Status: PARKED, v0.1, 2026-09-30. Joshua Marpet and Cairn Viktor.
Trigger to build: the first pilot organization that runs Linux servers (Windows next, then macOS).
Origin: Joshua, after "Your SBOM Is Fan Fiction" (yeet, 2026-09-24, https://yeet.cx/blog/your-sbom-is-fan-fiction).

## Purpose

Produce Observed-class evidence of what software is actually running, and compare it against the vendor's declared SBOM (Stated or Recorded class). A build-time SBOM describes the machine as built; this module describes the machine as it runs.

## Design rules

- Snapshot at collection time, sealed like every other package. No drivers, kernel extensions, eBPF, or resident agent.
- No new third-party runtime dependency. Do not build on yeet's daemon or GPL eBPF code (vendor neutrality and license).
- One evidence format on every OS: process, path, sha256, signer, version, load type (library, open file, runtime import).
- Needs root/admin to see every process; without it, record the coverage gap explicitly rather than silently under-report.

## What to collect, per OS

- Linux: /proc/<pid>/maps and /proc/<pid>/exe; "(deleted)" markers flag stale-in-memory libraries.
- Windows: loaded modules per process (Windows API or psutil); Authenticode signer and file version. If Sysmon is present, read event ID 7 (image loaded) instead of or in addition to the snapshot.
- macOS: mapped files via libproc (or lsof/vmmap); code signature (signer, cdhash). Apple system libraries sit in the dyld shared cache: identify by macOS version, not per-library hash. Apple-protected processes are out of reach.
- All OSes, for interpreted languages: open files (catches .jar files), plus runtime-reported imports where feasible (Python imported modules, Node require cache, JVM classpath). Without this, Python, Node and Java dependency coverage is poor.

## Findings

- Undeclared: running, not in the SBOM.
- Declared but absent: in the SBOM, never observed running.
- Stale in memory: library patched on disk but the old version still loaded (Linux marker; elsewhere compare loaded vs on-disk hash).

## Known limits (say them out loud)

- Statically linked code (Go, Rust, OpenSSL inside Node binaries) does not appear as a loaded library anywhere. Needs binary composition analysis, a different tool.
- Snapshot only: short-lived processes can be missed.

## Validation plan (the number we can quote)

On the pilot: take the vendor's SBOM, run the module, and report coverage (observed vs declared) broken down by language. Joshua's gut estimate for native code: it should catch a lot. Expected much lower for Python, Node and Java without the open-files and runtime-import pieces. Only the measured number goes into sales material.

## Separate, related fix

The Collector README says "open source" but names no license. Choose and add one (e.g., Apache-2.0) before any pilot.
