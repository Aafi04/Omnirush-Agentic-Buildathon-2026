# No native/system packages are needed beyond these pinned official images.
FROM node:22.19.0-bookworm-slim AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./frontend
RUN --network=none npm test && npm run build

FROM python:3.11.9-slim-bookworm AS backend
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml ./
COPY backend ./backend
COPY samples ./samples
COPY scripts/smoke.py ./scripts/smoke.py
COPY --from=frontend /app/frontend/dist ./frontend/dist
# Tests require no network or external service. Downloads happen above.
RUN --network=none python -m pytest -q

FROM backend AS runtime
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/api/health', timeout=2)"
CMD ["sh", "-c", "exec python -m uvicorn agenttrace.api:app --app-dir backend --host 0.0.0.0 --port ${PORT:-8000} --no-access-log"]
