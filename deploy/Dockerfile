FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/vguard

COPY pyproject.toml README.md requirements.txt ./
COPY src ./src

RUN pip install --no-cache-dir numpy && pip install --no-cache-dir -e .

EXPOSE 9190 9191

ENTRYPOINT ["vguard"]
CMD ["web"]