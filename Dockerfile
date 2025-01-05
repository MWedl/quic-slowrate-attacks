FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        gcc \
        libc6-dev \
    && curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="${PATH}:/root/.local/bin"

WORKDIR /app
COPY pyproject.toml poetry.lock /app/
COPY pylsqpack /app/pylsqpack
RUN poetry config virtualenvs.create false \
    && poetry install

COPY quic_slowrate_attacks /app/quic_slowrate_attacks
