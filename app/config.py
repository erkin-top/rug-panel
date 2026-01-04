# Copyright 2026 Erkin (https://erkin.top)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Конфигурация приложения WireGuard Panel
Все настройки можно переопределить через переменные окружения
Оптимизировано для работы в Docker
"""
import os
import secrets
from pathlib import Path

# Загрузка переменных окружения из .env файла
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # В Docker окружении python-dotenv может быть не установлен
    # т.к. переменные окружения передаются напрямую
    pass

# ==================== Базовые пути ====================
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(exist_ok=True)

# ==================== База данных ====================
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(DATA_DIR / "panel.db")))

# ==================== WireGuard конфигурация ====================
# В Docker всё хранится в /app/data
WG_CONFIG_PATH = Path(os.getenv("WG_CONFIG_PATH", str(DATA_DIR / "wg0.conf")))
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")

# ==================== Безопасность ====================
# Для продакшна обязательно установите SECRET_KEY через переменную окружения!
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 24)))  # 24 часа

# ==================== Сервер ====================
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# ==================== WireGuard настройки по умолчанию ====================
DEFAULT_WG_PORT = int(os.getenv("DEFAULT_WG_PORT", "51820"))
DEFAULT_DNS = os.getenv("DEFAULT_DNS", "77.88.8.8, 8.8.8.8")
DEFAULT_ALLOWED_IPS = os.getenv("DEFAULT_ALLOWED_IPS", "0.0.0.0/0, ::/0")
DEFAULT_PERSISTENT_KEEPALIVE = int(os.getenv("DEFAULT_PERSISTENT_KEEPALIVE", "25"))
# Внешний IP/домен сервера для клиентских конфигов (приоритет над автодетектом)
# Если задан - не будет затираться автоопределённым IP
WG_SERVER_ENDPOINT = os.getenv("WG_SERVER_ENDPOINT", "")

# ==================== Версия панели ====================
PANEL_VERSION = os.getenv("PANEL_VERSION", "1.4.3")

# ==================== Язык интерфейса ====================
# Поддерживаемые языки: ru (русский), en (английский)
LANGUAGE = os.getenv("LANGUAGE", "ru")

# ==================== UI / Frontend ====================
# Брендинг/пути лучше держать в конфиге, чтобы не разносить по шаблонам.
APP_NAME = os.getenv("APP_NAME", "Rug-Panel")
FAVICON_PATH = os.getenv("FAVICON_PATH", "/static/favicon.png")

# Источник HTMX (можно переопределить, например, на локальный /static/htmx.min.js)
HTMX_SRC = os.getenv("HTMX_SRC", "https://unpkg.com/htmx.org@1.9.10")

# ==================== UI значения по умолчанию ====================
# Адрес сервера WG по умолчанию (используется в форме server settings, если конфиг пуст)
DEFAULT_VPN_ADDRESS = os.getenv("DEFAULT_VPN_ADDRESS", "10.0.0.1/24")

# Плейсхолдер на случай, если не удаётся вычислить следующий IP
DEFAULT_PEER_ALLOWED_IPS_PLACEHOLDER = os.getenv("DEFAULT_PEER_ALLOWED_IPS_PLACEHOLDER", "10.0.0.X/32")

# WAN интерфейс по умолчанию (fallback, если определить автоматически не удалось)
DEFAULT_WAN_INTERFACE = os.getenv("DEFAULT_WAN_INTERFACE", "eth0")

# ==================== Кэширование ====================
CONFIG_CACHE_TTL = int(os.getenv("CONFIG_CACHE_TTL", "5"))  # Время жизни кэша конфига в секундах
STATUS_CACHE_TTL = int(os.getenv("STATUS_CACHE_TTL", "2"))  # Время жизни кэша статусов
QR_CACHE_SIZE = int(os.getenv("QR_CACHE_SIZE", "100"))  # Размер LRU кэша для QR кодов

# ==================== Логирование ====================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
