# SENTRY engine (Linux). Scans mounted paths read-only; remediation happens on the host.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends clamav clamdscan \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 sentry

WORKDIR /opt/sentry
COPY pyproject.toml README.md LICENSE ./
COPY sentry_engine ./sentry_engine
RUN pip install --no-cache-dir ".[full]"

USER sentry
ENV SENTRY_HOME=/home/sentry/.sentry
ENTRYPOINT ["sentry"]
CMD ["doctor"]
