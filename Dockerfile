FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.26@sha256:3d868e555f8f1dbc324afa005066cd11e1053fc4743b9808ca8025283e65efa5 /uv /usr/local/bin/uv
RUN apk add --no-cache git ca-certificates
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
COPY pyproject.toml uv.lock LICENSE NOTICE README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python \
    && /app/.venv/bin/python -c 'import auth_service.app'

COPY .github/workflows/third-party-notices/ /opt/legal-supplements/
COPY scripts/prepare_notices.py /opt/prepare_notices.py
RUN /app/.venv/bin/python -I /opt/prepare_notices.py /opt/notices /opt/legal-supplements

FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=build /opt/notices /usr/share/doc/auth-service/third-party
COPY LICENSE NOTICE /usr/share/doc/auth-service/
# Migrations are image-local owner resources, intentionally absent from wheels.
COPY src/auth_service/migrations /app/.venv/lib/python3.13/site-packages/auth_service/migrations
COPY src/auth_service/migrate.py /app/.venv/lib/python3.13/site-packages/auth_service/migrate.py
ARG GIT_SHA=unknown
ARG BUILT_AT=unknown
ENV PATH=/app/.venv/bin:$PATH GIT_SHA=${GIT_SHA} BUILT_AT=${BUILT_AT} \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/hyperme-sh/auth-service" \
      org.opencontainers.image.revision="${GIT_SHA}"
USER 65532:65532
EXPOSE 8000
CMD ["python", "-m", "auth_service.main"]
