FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/evals
WORKDIR /evals
COPY evals/runners/ runners/
COPY packages/agents/scam_shield/ scam_shield/
USER nobody

CMD ["python", "runners/validate_dataset.py", "datasets"]
