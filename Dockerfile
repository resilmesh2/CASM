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

RUN go install github.com/g0ldencybersec/EasyEASM/easyeasm@latest
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@latest
RUN go install github.com/owasp-amass/amass/v3/...@master
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0
RUN go install github.com/owasp-amass/oam-tools/cmd/oam_subs@master
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

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

COPY --chown=1001:1001 --from=build /app /app
COPY --chown=1001:1001 --from=build /venv /venv
COPY --from=go_build /usr/local/go /usr/local/go
COPY --chown=1001:1001 --from=go_build /app/go /app/go

RUN mkdir -p .config/amass
RUN chown -R 1001:1001 .config

USER 1001:1001

EXPOSE 8000

CMD ["/venv/bin/python", "-m", "easyeasm_demo.worker"]