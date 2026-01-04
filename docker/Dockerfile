# ================================
# Rug-Panel - Docker Build
# Легковесная панель управления WireGuard VPN
# Multi-stage сборка для оптимизации размера
# ================================

# ==================== Stage 1: Build ====================
FROM python:3.11-slim AS build

WORKDIR /app

# Установка build-зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Копирование и установка зависимостей с retry и увеличенным таймаутом
COPY requirements.txt .
RUN pip install --no-cache-dir --user --timeout=120 --retries=5 -r requirements.txt

# ==================== Stage 2: Production ====================
FROM python:3.11-slim

WORKDIR /app

# OCI Labels (стандарт Open Container Initiative)
LABEL org.opencontainers.image.source="https://github.com/erkin-top/rug-panel"
LABEL org.opencontainers.image.title="Rug-Panel"
LABEL org.opencontainers.image.description="Легковесная панель управления WireGuard VPN"
LABEL org.opencontainers.image.version="1.4.3"
LABEL org.opencontainers.image.vendor="Erkin"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.documentation="https://github.com/erkin-top/rug-panel/blob/main/README.md"
LABEL maintainer="Erkin <contact@erkin.top>"

# Системные зависимости для WireGuard + dumb-init для правильной обработки сигналов
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    iptables \
    kmod \
    curl \
    qrencode \
    dumb-init \
    openresolv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Настройка iptables-legacy для совместимости (как в wg-easy)
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true

# Копирование зависимостей из build stage
COPY --from=build /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Копирование приложения
COPY app/ ./app/
COPY static/ ./static/
COPY run.py .
COPY docker/entrypoint.sh ./entrypoint.sh

# Права на выполнение
RUN chmod +x entrypoint.sh

# Создание директории для данных
RUN mkdir -p /app/data

# Переменные окружения по умолчанию
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    DEBUG=false \
    WG_CONFIG_PATH=/app/data/wg0.conf \
    WG_INTERFACE=wg0 \
    DATA_DIR=/app/data \
    DATABASE_PATH=/app/data/panel.db \
    LOG_LEVEL=INFO

# Порт приложения
EXPOSE 8000

# Healthcheck (аналогично wg-easy)
HEALTHCHECK --interval=1m --timeout=5s --retries=3 --start-period=30s \
    CMD curl -sf http://localhost:${PORT:-8000}/login || exit 1

# Точка входа с dumb-init для правильной обработки сигналов PID 1
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/app/entrypoint.sh"]
