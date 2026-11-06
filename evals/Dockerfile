FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /evals
COPY runners/ runners/
USER nobody

CMD ["python", "runners/validate_dataset.py", "datasets"]
