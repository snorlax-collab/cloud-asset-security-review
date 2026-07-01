# Minimal, non-root image for the ephemeral scanner.
# Stdlib-first design means few dependencies -> small image, fast cold start,
# small attack surface (important for a container that touches untrusted targets).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
# [llm] = Claude review, [aws] = SQS publisher/worker for the scalable path.
RUN pip install --no-cache-dir ".[llm,aws]" && \
    useradd --uid 65534 --no-create-home scanner 2>/dev/null || true && \
    mkdir -p /reports && chown 65534:65534 /reports

ENV PYTHONUNBUFFERED=1
USER 65534

# Default: print help. Override per invocation, e.g.:
#   docker run --rm asset-scanner scan --host example.com --json
ENTRYPOINT ["asset-review"]
CMD ["info"]
