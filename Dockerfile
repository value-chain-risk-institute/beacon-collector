# Beacon Collector — dogfood image for the JawnCon deployment.
# Purpose: run the OPEN VCRI collector on a real box, scan the box's own posture,
# seal it locally. Outbound-only by design: this image opens NO listening ports.
# The public IP is the box's problem (harden the OS + Security Onion / Wazuh);
# the collector never listens, so it is not the attack surface. See README.md.

FROM python:3.12-slim

# Trivy version is a build arg so the image is reproducible.
# VERIFY this is a current Trivy release before building; do not trust it blindly.
ARG TRIVY_VERSION=0.58.1

# System layer: install Trivy (the only external tool the collector shells out to),
# then remove the tooling used to fetch it. No daemons, no services.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates openssl \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Collector source. Copy the modules explicitly so image contents are auditable.
COPY *.py /app/
# TSA trust chain, so `anchor.py verify` works offline inside the image.
COPY anchor-trust /app/anchor-trust
COPY dogfood.sh /app/dogfood.sh
RUN chmod +x /app/dogfood.sh

# Least privilege: run as a non-root user. The host filesystem is mounted read-only
# at /host (see docker-compose.yml); a non-root reader covers the vast majority of
# posture-relevant files. If a full-root scan is ever required, that is an explicit,
# documented deviation, not the default.
RUN useradd --create-home --uid 10001 beacon \
 && mkdir -p /out && chown beacon:beacon /out
USER beacon
# The container filesystem is read-only; the OpenTimestamps client keeps a small
# calendar cache, so point it at the tmpfs rather than the read-only home.
ENV XDG_CACHE_HOME=/tmp/cache

# Evidence output lands in /out (mount a volume there to keep the sealed package).
VOLUME ["/out"]

# Default: dogfood the box. Override the entrypoint for `verify`, `merge`, etc.
ENTRYPOINT ["/app/dogfood.sh"]
