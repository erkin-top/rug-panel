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
Централизованные зависимости приложения (Dependency Injection)
Устраняет дублирование кода и обеспечивает единую точку конфигурации

ОПТИМИЗАЦИИ:
- Thread-safe singleton с double-checked locking
- Оптимизированные хелперы без лишних аллокаций
- Предкомпилированный URL encoder
"""
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import threading
import time
import ipaddress
from typing import List, Dict, Optional

from app.config import (
    WG_CONFIG_PATH,
    WG_INTERFACE,
    PANEL_VERSION,
    APP_NAME,
    FAVICON_PATH,
    HTMX_SRC,
    DEFAULT_DNS,
    DEFAULT_PERSISTENT_KEEPALIVE,
    DEFAULT_VPN_ADDRESS,
    DEFAULT_WG_PORT,
    LANGUAGE,
)
from app.wireguard import WGManager
from app.i18n import get_translations


# ==================== Jinja2 Templates ====================
# Единственный экземпляр шаблонизатора для всего приложения

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Cache-busting для статики: браузер может кэшировать /static/* до суток.
_static_css_path = BASE_DIR.parent / "static" / "style.css"
try:
    # Наносекунды, чтобы версия менялась даже при быстрых правках
    _static_css_mtime = _static_css_path.stat().st_mtime_ns
except OSError:
    _static_css_mtime = time.time_ns()

templates.env.globals["static_version"] = f"{PANEL_VERSION}-{_static_css_mtime}"

# Общие UI-глобалы (убирают хардкод в шаблонах)
templates.env.globals["panel_version"] = PANEL_VERSION
templates.env.globals["app_name"] = APP_NAME
templates.env.globals["favicon_path"] = FAVICON_PATH
templates.env.globals["htmx_src"] = HTMX_SRC

# Дефолты для форм/шаблонов
templates.env.globals["default_dns"] = DEFAULT_DNS
templates.env.globals["default_keepalive"] = DEFAULT_PERSISTENT_KEEPALIVE
templates.env.globals["default_vpn_address"] = DEFAULT_VPN_ADDRESS
templates.env.globals["default_wg_port"] = DEFAULT_WG_PORT

# Переводы интерфейса
templates.env.globals["t"] = get_translations()
templates.env.globals["lang"] = LANGUAGE


def urlencode_full(value: str) -> str:
    """Кастомный фильтр для полного URL-кодирования (включая /)"""
    return quote(str(value), safe='')


# Регистрируем фильтр один раз
templates.env.filters['urlencode_full'] = urlencode_full


# ==================== WireGuard Manager ====================
# Thread-safe Singleton для WGManager

_wg_manager: Optional[WGManager] = None
_wg_manager_lock = threading.Lock()


def get_wg_manager() -> WGManager:
    """
    Dependency для получения WG менеджера.
    Thread-safe singleton с double-checked locking.
    """
    global _wg_manager
    if _wg_manager is None:
        with _wg_manager_lock:
            if _wg_manager is None:
                _wg_manager = WGManager(WG_CONFIG_PATH, WG_INTERFACE)
    return _wg_manager


def reset_wg_manager():
    """Сброс менеджера (для тестов или пересоздания)"""
    global _wg_manager
    with _wg_manager_lock:
        _wg_manager = None


# ==================== Helper Functions ====================

def build_peers_with_status(peers: List[Dict], statuses: Dict) -> List[Dict]:
    """
    Обогащение списка пиров статусами.
    Оптимизация: минимум аллокаций, прямой доступ к dict.
    
    Args:
        peers: Список пиров из конфига
        statuses: Словарь статусов {public_key: status_dict}
    
    Returns:
        Список словарей с 'peer' и 'status'
    """
    # Предаллокация списка нужного размера
    result = [None] * len(peers)
    
    for i, peer in enumerate(peers):
        public_key = peer.get('PublicKey', '')
        # Используем get с дефолтным значением - быстрее чем проверка + доступ
        status = statuses.get(public_key) or {}
        result[i] = {'peer': peer, 'status': status}
    
    return result


def count_online_peers(peers: List[Dict], statuses: Dict) -> int:
    """
    Подсчёт онлайн пиров.
    Оптимизация: использование sum с генератором.
    """
    return sum(
        1 for peer in peers
        if statuses.get(peer.get('PublicKey', ''), {}).get('is_online')
    )


def get_stats(peers: List[Dict], statuses: Dict) -> Dict:
    """
    Получение статистики пиров.
    Оптимизация: один проход вместо вызова count_online_peers.
    """
    total = len(peers)
    online = 0
    
    for peer in peers:
        public_key = peer.get('PublicKey', '')
        if statuses.get(public_key, {}).get('is_online'):
            online += 1
    
    return {
        "total": total,
        "online": online,
        "offline": total - online
    }


# ==================== Response Helpers ====================
# Устранение дублирования шаблонных ответов

def alert_response(
    request,
    alert_type: str,
    message: str,
    status_code: int = 200
):
    """
    Унифицированный ответ с алертом.
    Устраняет дублирование templates.TemplateResponse("components/alert.html", ...)
    
    Args:
        request: FastAPI Request объект
        alert_type: Тип алерта ("error", "success", "warning", "info")
        message: Текст сообщения
        status_code: HTTP статус код (по умолчанию 200)
    """
    return templates.TemplateResponse(
        request,
        "components/alert.html",
        {"type": alert_type, "message": message},
        status_code=status_code
    )


def modal_alert_response(request, alert_type: str, message: str):
    """
    Унифицированный ответ с модальным алертом.
    Устраняет дублирование templates.TemplateResponse("components/modal_alert.html", ...)
    """
    return templates.TemplateResponse(
        request,
        "components/modal_alert.html",
        {"type": alert_type, "message": message}
    )


def peers_list_response(
    request,
    wg,
    success_message: Optional[str] = None
):
    """
    Унифицированный ответ со списком пиров.
    Устраняет дублирование паттерна:
        interface, peers = wg.load_config()
        statuses = wg.get_peers_status()
        peers_with_status = build_peers_with_status(peers, statuses)
        return templates.TemplateResponse(...)
    
    Args:
        request: FastAPI Request объект
        wg: WGManager instance
        success_message: Опциональное сообщение об успехе
    """
    interface, peers = wg.load_config()
    statuses = wg.get_peers_status()
    peers_with_status = build_peers_with_status(peers, statuses)

    # Сортировка по IP адресу (единый порядок для list/add/update/delete/toggle)
    def get_ip_key(item: Dict):
        try:
            ip_str = item['peer'].get('AllowedIPs', '').split(',')[0].strip()
            if '/' in ip_str:
                ip_str = ip_str.split('/')[0]
            return ipaddress.ip_address(ip_str)
        except Exception:
            return ipaddress.ip_address('0.0.0.0')

    peers_with_status.sort(key=get_ip_key)
    
    context = {"peers": peers_with_status}
    if success_message:
        context["success"] = success_message
    
    return templates.TemplateResponse(request, "components/peers_list.html", context)


def users_list_response(
    request,
    current_user_id: int,
    success_message: Optional[str] = None
):
    """
    Унифицированный ответ со списком пользователей.
    Устраняет дублирование паттерна:
        users = UserDB.get_all_users()
        return templates.TemplateResponse("components/users_list.html", {...})
    
    Args:
        request: FastAPI Request объект
        current_user_id: ID текущего пользователя
        success_message: Опциональное сообщение об успехе
    """
    from app.database import UserDB
    users = UserDB.get_all_users()
    
    context = {
        "users": users,
        "current_user_id": current_user_id
    }
    if success_message:
        context["success"] = success_message
    
    return templates.TemplateResponse(request, "components/users_list.html", context)
