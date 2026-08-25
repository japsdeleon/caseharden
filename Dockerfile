# One image, seven services. Which agent runs is an environment variable, because
# the detectors really are one program and pretending otherwise with six
# Dockerfiles would be six things to keep in step.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY agents/requirements.txt /app/agents/requirements.txt
RUN pip install --no-cache-dir -r /app/agents/requirements.txt

COPY caseharden /app/caseharden
COPY agents /app/agents

# CASEHARDEN_AGENT picks the directory; CASEHARDEN_CHECK_FAMILY picks the check.
ENV CASEHARDEN_AGENT=detector
CMD ["python", "/app/agents/serve.py"]
