FROM python:3.12-bookworm as build

WORKDIR /app

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN curl -sSL https://install.python-poetry.org | python3 - && \
    python -m venv /venv

COPY . ./
RUN . /venv/bin/activate && ~/.local/bin/poetry install

FROM golang:1.24.0-bookworm as go_build

RUN go install github.com/g0ldencybersec/EasyEASM/easyeasm@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@v0.0.4 && \
    go install github.com/owasp-amass/amass/v3/...@master && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0 && \
    go install github.com/owasp-amass/oam-tools/cmd/oam_subs@master && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.8


RUN mkdir -p /app/go/bin
RUN cp /go/bin/* /app/go/bin

FROM python:3.12-slim-bookworm as runtime

ENV VIRTUAL_ENV=/venv \
	PATH=/venv/bin:/app/go/bin:/usr/local/go/bin:$PATH \
	PYTHONFAULTHANDLER=1 \
    PYTHONBUFFERED=1

WORKDIR /app

RUN groupadd -g 1001 app && \
    useradd -u 1001 -g app -s /bin/sh -d /app app

COPY --from=build /app /app
COPY --from=build /venv /venv
COPY --from=go_build /usr/local/go /usr/local/go
COPY --from=go_build /app/go /app/go

RUN mkdir -p .config/amass
RUN chown -R 1001:1001 .config

USER 1001:1001

EXPOSE 8000

CMD ["/venv/bin/python", "-m", "temporal.easm.worker"]