#!/bin/bash
# ================================
# Rug-Panel - Entrypoint Script
# Автоматическая инициализация WireGuard и панели
# ================================

set -e

echo "========================================="
echo "🚀 Rug-Panel Starting..."
echo "========================================="

# Создание директории для данных
mkdir -p /app/data
mkdir -p /etc/wireguard

# Создание симлинка для wg-quick (он ищет конфиги в /etc/wireguard/)
if [ ! -L "/etc/wireguard/wg0.conf" ]; then
    ln -sf /app/data/wg0.conf /etc/wireguard/wg0.conf
    echo "✓ Симлинк /etc/wireguard/wg0.conf -> /app/data/wg0.conf создан"
fi

# Проверка и создание конфигурации WireGuard
if [ ! -f "/app/data/wg0.conf" ]; then
    echo "📝 Создание начальной конфигурации WireGuard..."
    
    # Генерация ключей
    PRIVATE_KEY=$(wg genkey)
    PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
    
    # Определение внешнего IP
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
    
    # Создание конфига с правильными правилами изоляции
    # По умолчанию: NAT включен, Forwarding включен
    NET_IFACE=$(ip route show default | grep -oP 'dev \K\S+' || echo "eth0")
    
    cat > /app/data/wg0.conf << EOF
# ServerEndpoint: ${SERVER_IP}:${DEFAULT_WG_PORT:-51820}
# EnableNAT: true
# EnableForwarding: true
# NetworkInterface: ${NET_IFACE}
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = ${DEFAULT_WG_PORT:-51820}
PostUp = iptables -D FORWARD -i %i -o ${NET_IFACE} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i ${NET_IFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i %i -o %i -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i %i -j DROP 2>/dev/null || true; iptables -D FORWARD -o %i -j DROP 2>/dev/null || true; iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || true; iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ${NET_IFACE} -j MASQUERADE; iptables -I FORWARD 1 -i %i -o ${NET_IFACE} -j ACCEPT; iptables -I FORWARD 1 -i ${NET_IFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -I FORWARD 1 -i %i -o %i -j ACCEPT; iptables -A FORWARD -i %i -j DROP; iptables -A FORWARD -o %i -j DROP
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i %i -o ${NET_IFACE} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i ${NET_IFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i %i -o %i -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i %i -j DROP 2>/dev/null || true; iptables -D FORWARD -o %i -j DROP 2>/dev/null || true

EOF
    
    echo "✓ Конфигурация создана"
    echo "✓ Server Public Key: $PUBLIC_KEY"
    echo "✓ Server IP: $SERVER_IP"
fi

# Установка правильных прав доступа к конфигу
chmod 600 /app/data/wg0.conf 2>/dev/null || true

# Проверка существующей конфигурации
if [ -f "/app/data/wg0.conf" ]; then
    echo "✓ Конфигурация WireGuard найдена"
fi

# Попытка загрузить модуль WireGuard (только в полноценном Linux)
echo "🔧 Проверка WireGuard..."
if modprobe wireguard 2>/dev/null; then
    echo "✓ Модуль WireGuard загружен"
    
    # Запуск WireGuard через симлинк в /etc/wireguard
    echo "🌐 Запуск WireGuard интерфейса..."
    if wg-quick up wg0 2>&1; then
        echo "✓ WireGuard запущен"
    else
        echo "⚠ Ошибка запуска wg-quick, попытка ручной настройки..."
        if ! ip link show wg0 >/dev/null 2>&1; then
            ip link add dev wg0 type wireguard 2>/dev/null || true
            wg setconf wg0 /app/data/wg0.conf 2>/dev/null || true
            ip address add 10.0.0.1/24 dev wg0 2>/dev/null || true
            ip link set up dev wg0 2>/dev/null || true
            echo "✓ WireGuard настроен вручную (без iptables правил - они будут применены при перезапуске)"
        fi
    fi
    
    # Проверка состояния
    if wg show wg0 >/dev/null 2>&1; then
        echo "✓ WireGuard работает"
    else
        echo "⚠ WireGuard не удалось запустить"
    fi
else
    echo "⚠ Модуль WireGuard недоступен (возможно Docker Desktop на Windows/Mac)"
    echo "⚠ WireGuard будет недоступен, но панель управления запустится"
fi

echo "========================================="
echo "✓ Инициализация завершена"
echo "🌐 Панель доступна на порту 8000"
echo "========================================="

# Запуск панели управления
exec python run.py
