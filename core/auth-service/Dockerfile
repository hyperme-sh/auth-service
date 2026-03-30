FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/auth-service ./core/auth-service
RUN uv sync --frozen --package auth-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src
WORKDIR /app/core/auth-service
CMD ["uv", "run", "--project", "/app/core/auth-service", "python", "-m", "auth_service.main"]
