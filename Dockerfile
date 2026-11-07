FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.11.26
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
COPY pyproject.toml uv.lock LICENSE README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python \
    && /app/.venv/bin/python -c 'import auth_service.app'

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
# Migrations are image-local owner resources, intentionally absent from wheels.
COPY src/auth_service/migrations /app/.venv/lib/python3.13/site-packages/auth_service/migrations
COPY src/auth_service/migrate.py /app/.venv/lib/python3.13/site-packages/auth_service/migrate.py
ARG GIT_SHA=unknown
ARG BUILT_AT=unknown
ENV PATH=/app/.venv/bin:$PATH GIT_SHA=${GIT_SHA} BUILT_AT=${BUILT_AT} \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
LABEL org.opencontainers.image.source="https://github.com/hyperme-sh/auth-service" \
      org.opencontainers.image.revision="${GIT_SHA}"
USER 65532:65532
EXPOSE 8000
CMD ["python", "-m", "auth_service.main"]
