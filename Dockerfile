# Multi-stage minimal production image for DrillOps
FROM python:3.12-slim as runtime

LABEL maintainer="DrillOps Team <https://github.com/redintDev/drillops>"
LABEL description="DrillOps: Automated Database Restore Drill Runner & SOC2 Compliance Certifier"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PAGER=cat \
    PGPAGER=cat

# Install essential database client tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package and install
COPY pyproject.toml README.md /app/
COPY drillops /app/drillops

RUN pip install --no-cache-dir .

# Create volume mountpoints
RUN mkdir -p /backups /certificates

EXPOSE 8787

ENTRYPOINT ["drillops"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8787", "--out", "/certificates"]
