FROM python:3.12-bookworm AS build

WORKDIR /app

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN curl -sSL https://install.python-poetry.org | python3 - && \
    python -m venv /venv

COPY . ./
RUN . /venv/bin/activate && ~/.local/bin/poetry install

FROM python:3.12-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/venv \
	PATH=/venv/bin:/app/go/bin:/usr/local/go/bin:$PATH \
	PYTHONFAULTHANDLER=1 \
    PYTHONBUFFERED=1

WORKDIR /app

COPY --from=build /app /app
COPY --from=build /venv /venv

CMD ["/venv/bin/python", "-m", "temporal.slp_enrichment.worker_schedule"]