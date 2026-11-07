FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app PYTHONUNBUFFERED=1
WORKDIR /app
COPY apps/web/ ./
COPY packages/agents/scam_shield/ scam_shield/
USER nobody

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8080"]
