FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    dbus \
    network-manager \
    network-manager-l2tp \
    network-manager-openvpn \
    strongswan \
    xl2tpd \
    ppp \
    iputils-ping \
    fping \
    iproute2 \
    netcat-openbsd \
    openssh-client \
    inetutils-telnet \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create storage directory
RUN mkdir -p /app/storage/backups

# Expose port
EXPOSE 8000

# Run application
CMD ["sh", "-lc", "exec gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --workers ${APP_WEB_WORKERS:-3} --max-requests ${APP_WEB_MAX_REQUESTS:-1500} --max-requests-jitter ${APP_WEB_MAX_REQUESTS_JITTER:-150} --timeout ${APP_WEB_TIMEOUT_SECONDS:-120} --graceful-timeout ${APP_WEB_GRACEFUL_TIMEOUT_SECONDS:-30} --keep-alive ${APP_WEB_KEEPALIVE_SECONDS:-10}"]
