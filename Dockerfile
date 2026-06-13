FROM python:3.11-slim AS builder

WORKDIR /build
COPY . .

RUN pip install --no-cache-dir build && \
    python -m build --wheel

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    netcat-openbsd \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

RUN adduser --disabled-password --gecos '' vulnsync
USER vulnsync

ENTRYPOINT ["vulnsync"]
CMD ["--help"]
