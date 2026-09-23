# Evidence bundle: NIST SP 800-171 Rev. 2 (110 security requirements)

Contents: `package.json` (the sealed evidence package; `blobs/` if raw tool output was captured), `coverage.json`, `coverage.md`, `index.html` (the same coverage report, three forms).

Verify the seal before trusting anything here: `python3 collector.py verify package.json` (or `beaconlib.verify_package`). A tampered package fails closed.

This bundle shows where sealed evidence speaks to each requirement and the class of that evidence. Not an assessment. Not an SPRS score. Not a determination that any requirement is implemented. No score is assigned by the collector; leveling and any verified rating are separate and independent.
