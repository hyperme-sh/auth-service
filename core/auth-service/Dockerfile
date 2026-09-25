FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY scripts/alembic_head.py /tmp/alembic_head.py
ARG ALEMBIC_HEAD
# Bake the Alembic head from the migrations copied above. See scripts/alembic_head.py.
RUN python3 /tmp/alembic_head.py \
      --versions /app/core/lib/controlplane-db/src/controlplane_db/alembic/versions \
      --write /alembic-head \
      --expect "${ALEMBIC_HEAD}"
LABEL com.fyberlabs.alembic-head="${ALEMBIC_HEAD}"
COPY core/events ./core/events
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/auth-service ./core/auth-service
# --no-dev skips panopticon-tests so the image does not need core/tests.
# uv run must use the same flags or it re-resolves the missing workspace member.
RUN uv sync --frozen --no-dev --package auth-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/core/auth-service/src
WORKDIR /app/core/auth-service
CMD ["uv", "run", "--frozen", "--no-dev", "--project", "/app/core/auth-service", "python", "-m", "auth_service.main"]
