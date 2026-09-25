FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir /app

WORKDIR /data
EXPOSE 8443

CMD ["reality-vpn", "server", "0.0.0.0"]
