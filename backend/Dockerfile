FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV http_proxy=""
ENV https_proxy=""
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV all_proxy=""
ENV ALL_PROXY=""
ENV no_proxy="*"
ENV NO_PROXY="*"
ENV PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_DEFAULT_TIMEOUT=120

RUN rm -f /etc/apt/apt.conf.d/proxy.conf 2>/dev/null || true     && echo 'Acquire::http::Proxy "false";' > /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::https::Proxy "false";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::https::Timeout "30";' >> /etc/apt/apt.conf.d/99-no-proxy     && apt-get update     && apt-get install -y --no-install-recommends gcc libpq-dev libffi-dev python3-venv     && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements-lock.txt README.md ./
RUN python -m venv /app/.venv     && /app/.venv/bin/pip install --upgrade pip setuptools wheel     && /app/.venv/bin/pip install --retries 5 -r requirements-lock.txt     && /app/.venv/bin/pip install --retries 5 "psycopg[binary]>=3.2.1"

COPY . .
RUN /app/.venv/bin/pip install --no-deps -e . \
    && /app/.venv/bin/python -m arq --help >/dev/null

FROM python:3.12-slim-bookworm AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV http_proxy=""
ENV https_proxy=""
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV all_proxy=""
ENV ALL_PROXY=""
ENV no_proxy="*"
ENV NO_PROXY="*"

RUN rm -f /etc/apt/apt.conf.d/proxy.conf 2>/dev/null || true     && echo 'Acquire::http::Proxy "false";' > /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::https::Proxy "false";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/99-no-proxy     && echo 'Acquire::https::Timeout "30";' >> /etc/apt/apt.conf.d/99-no-proxy     && apt-get update     && apt-get install -y --no-install-recommends         libpq5         curl         git         openssh-client         libpango-1.0-0         libpangoft2-1.0-0         libpangocairo-1.0-0         libcairo2         libgdk-pixbuf-2.0-0         libglib2.0-0         shared-mime-info         fonts-noto-cjk     && fc-cache -fv     && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv
COPY . .

RUN mkdir -p /app/uploads/zip_files     && sed -i 's/\r$//' /app/docker-entrypoint.sh     && chmod +x /app/docker-entrypoint.sh

EXPOSE 8000
CMD ["/app/docker-entrypoint.sh"]
