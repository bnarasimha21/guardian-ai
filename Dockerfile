# GuardianAI server: POST /api/check, the approvals API and the dashboard.
# One process per container. Shared state (approvals, audit log) lives in
# Postgres, so the Helm chart runs several of these side by side.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py targets.json ./
COPY backend ./backend
COPY frontend ./frontend
COPY policies ./policies
COPY evals ./evals

# The server keeps per-session observer targets in /app/sessions; the chart
# mounts an emptyDir there so the root filesystem can be read-only.
RUN useradd --uid 10001 --no-create-home guardian && mkdir /app/sessions && chown guardian /app/sessions
USER 10001

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
