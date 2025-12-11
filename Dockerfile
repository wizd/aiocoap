# syntax=docker/dockerfile:1

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AIOCOAP_DTLSSERVER_ENABLED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
        libtool \
        autoconf \
        automake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install ".[all]"

ENTRYPOINT ["python", "/app/docker/entrypoint.py"]

