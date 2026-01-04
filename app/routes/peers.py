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
Роуты управления WireGuard пирами

ОПТИМИЗАЦИИ:
- LRU кэширование QR кодов
- Переиспользование объектов qrcode
- Оптимизированная генерация PNG
"""
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse
from typing import Optional
import qrcode
import io
import base64
import ipaddress
from functools import lru_cache
import hashlib

from app.auth import require_auth
from app.wireguard import WGManager
from app.config import (
    WG_CONFIG_PATH,
    QR_CACHE_SIZE,
    DEFAULT_DNS,
    DEFAULT_PERSISTENT_KEEPALIVE,
    DEFAULT_PEER_ALLOWED_IPS_PLACEHOLDER,
)
from app.dependencies import (
    templates,
    get_wg_manager,
    alert_response,
    modal_alert_response,
    peers_list_response,
)

router = APIRouter(prefix="/peers", tags=["peers"])

# Переиспользуемый объект QR для экономии памяти
_qr_instance = None


def _get_qr_instance():
    """Получить переиспользуемый QR instance"""
    global _qr_instance
    if _qr_instance is None:
        _qr_instance = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Быстрее
            box_size=10,
            border=4  # Меньше border = меньше размер
        )
    return _qr_instance


@lru_cache(maxsize=QR_CACHE_SIZE)
def _cached_qr_code(data_hash: str, data: str) -> str:
    """
    Кэшированная генерация QR кода.
    Используем hash в ключе для LRU cache (data может быть слишком длинной).
    """
    qr = _get_qr_instance()
    qr.clear()  # Очистка для переиспользования
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG', optimize=True)
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()


def generate_qr_code(data: str) -> str:
    """Генерация QR-кода в base64 (с кэшированием)"""
    # Вычисляем hash для использования как ключ кэша
    data_hash = hashlib.md5(data.encode()).hexdigest()
    return _cached_qr_code(data_hash, data)


@router.get("/", response_class=HTMLResponse)
async def peers_list(
    request: Request,
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Список всех пиров (HTMX partial)"""
    try:
        return peers_list_response(request, wg)
    except FileNotFoundError:
        return alert_response(request, "warning", 
            f"Конфигурационный файл WireGuard не найден: {WG_CONFIG_PATH}")
    except Exception as e:
        return alert_response(request, "error", 
            f"Ошибка загрузки конфигурации: {str(e)}")


@router.get("/add-form", response_class=HTMLResponse)
async def add_peer_form(
    request: Request,
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Форма добавления нового пира"""
    try:
        next_ip = wg.get_next_available_ip()
    except Exception:
        next_ip = DEFAULT_PEER_ALLOWED_IPS_PLACEHOLDER
    
    return templates.TemplateResponse(request, "components/peer_form.html", {
        "next_ip": next_ip,
        "mode": "add"
    })


@router.post("/add")
async def add_peer(
    request: Request,
    name: str = Form(...),
    allowed_ips: str = Form(...),
    persistent_keepalive: int = Form(DEFAULT_PERSISTENT_KEEPALIVE),
    dns: str = Form(DEFAULT_DNS),
    use_preshared_key: bool = Form(False),
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Добавление нового пира"""
    import re
    try:
        if not name or len(name.strip()) < 1:
            return alert_response(request, "error", "Имя клиента обязательно")
        
        # Валидация имени - только латиница, цифры, пробелы, дефисы, точки, подчёркивания
        if not re.match(r'^[A-Za-z0-9_\-\s\.]+$', name.strip()):
            return alert_response(request, "error", "Имя должно содержать только латинские буквы, цифры, пробелы, дефисы, точки и подчёркивания")
        
        new_peer, client_config = wg.add_peer(
            name=name.strip(),
            allowed_ips=allowed_ips.strip(),
            preshared_key=use_preshared_key,
            persistent_keepalive=persistent_keepalive,
            dns=dns.strip()
        )
        
        # Генерируем QR-код
        qr_code = generate_qr_code(client_config)
        
        # Перезагружаем конфиг WireGuard (игнорируем ошибки если нет прав)
        try:
            wg.reload_config()
        except Exception:
            pass  # Конфиг сохранён, применение требует root
        
        return templates.TemplateResponse(request, "components/peer_created.html", {
            "peer": new_peer,
            "client_config": client_config,
            "qr_code": qr_code
        })
    except Exception as e:
        return alert_response(request, "error", f"Ошибка создания пира: {str(e)}")


@router.get("/edit", response_class=HTMLResponse)
async def edit_peer_form(
    request: Request,
    key: str,  # Query parameter
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Форма редактирования пира"""
    try:
        interface, peers = wg.load_config()
        peer = next((p for p in peers if p.get('PublicKey') == key), None)
        
        if not peer:
            return alert_response(request, "error", "Пир не найден")
        
        return templates.TemplateResponse(request, "components/peer_edit_form.html", {
            "peer": peer
        })
    except Exception as e:
        return alert_response(request, "error", f"Ошибка: {str(e)}")


@router.put("/update")
async def update_peer(
    request: Request,
    key: str,  # Query parameter - старый PublicKey
    name: str = Form(...),
    allowed_ips: str = Form(...),
    persistent_keepalive: int = Form(DEFAULT_PERSISTENT_KEEPALIVE),
    public_key: str = Form(None),  # Новый публичный ключ (опционально)
    use_preshared_key: bool = Form(False),  # Чекбокс для PresharedKey
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Обновление пира"""
    import re
    try:
        # Валидация имени - только латиница
        if not re.match(r'^[A-Za-z0-9_\-\s\.]+$', name.strip()):
            return alert_response(request, "error", "Имя должно содержать только латинские буквы, цифры, пробелы, дефисы, точки и подчёркивания")
        
        updates = {
            'name': name.strip(),
            'allowed_ips': allowed_ips.strip(),
            'persistent_keepalive': persistent_keepalive,
            'use_preshared_key': use_preshared_key
        }
        
        # Если передан новый PublicKey и он отличается от старого
        if public_key and public_key.strip() != key:
            updates['new_public_key'] = public_key.strip()
        
        if wg.update_peer(key, updates):
            try:
                wg.reload_config()
            except Exception:
                pass  # Конфиг сохранён, применение требует root
            return peers_list_response(request, wg, f"Клиент {name} обновлён")
        else:
            return alert_response(request, "error", "Пир не найден")
    except Exception as e:
        return alert_response(request, "error", f"Ошибка обновления: {str(e)}")


@router.delete("/delete")
async def delete_peer(
    request: Request,
    key: str,  # Query parameter
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Удаление пира"""
    try:
        if wg.delete_peer(key):
            try:
                wg.reload_config()
            except Exception:
                pass  # Конфиг сохранён, применение требует root
            return peers_list_response(request, wg, "Клиент удалён")
        else:
            return alert_response(request, "error", "Пир не найден")
    except Exception as e:
        return alert_response(request, "error", f"Ошибка удаления: {str(e)}")


@router.post("/toggle")
async def toggle_peer(
    request: Request,
    key: str,  # Query parameter
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Включение/отключение пира"""
    try:
        new_state = wg.toggle_peer(key)
        
        if new_state is not None:
            try:
                wg.reload_config()
            except Exception:
                pass  # Конфиг сохранён, применение требует root
            state_text = "включен" if new_state else "отключен"
            return peers_list_response(request, wg, f"Клиент {state_text}")
        else:
            return alert_response(request, "error", "Пир не найден")
    except Exception as e:
        return alert_response(request, "error", f"Ошибка: {str(e)}")


@router.get("/config", response_class=PlainTextResponse)
async def download_peer_config(
    request: Request,
    key: str,  # Query parameter - PublicKey
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Скачивание конфига клиента"""
    try:
        # Получаем endpoint сервера из настроек
        interface, peers = wg.load_config()
        
        # Ищем peer по ключу
        peer = None
        for p in peers:
            if p.get('PublicKey') == key:
                peer = p
                break
        
        if not peer:
            return PlainTextResponse(
                content="# Клиент не найден",
                media_type="text/plain",
                status_code=404
            )
        
        # Генерируем конфиг
        config = wg.get_client_config(key)
        
        if not config:
            return PlainTextResponse(
                content="# Приватный ключ клиента не сохранён\n# Конфигурация была доступна только при создании клиента",
                media_type="text/plain"
            )
        
        # Возвращаем конфиг как скачиваемый файл
        peer_name = peer.get('_name', 'client').replace(' ', '_')
        from fastapi.responses import Response
        return Response(
            content=config,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={peer_name}.conf"}
        )
    except Exception as e:
        return PlainTextResponse(
            content=f"# Ошибка: {str(e)}",
            media_type="text/plain",
            status_code=500
        )


@router.get("/qr", response_class=HTMLResponse)
async def get_peer_qr(
    request: Request,
    key: str,  # Query parameter - PublicKey
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Получение QR кода для существующего клиента"""
    try:
        interface, peers = wg.load_config()
        
        # Ищем peer по ключу
        peer = None
        for p in peers:
            if p.get('PublicKey') == key:
                peer = p
                break
        
        if not peer:
            return modal_alert_response(request, "error", "Клиент не найден")
        
        # Генерируем конфиг
        config = wg.get_client_config(key)
        
        if not config:
            return modal_alert_response(request, "warning", 
                "Приватный ключ клиента не сохранён. QR код был доступен только при создании.")
        
        # Генерируем QR код
        qr_base64 = generate_qr_code(config)
        
        return templates.TemplateResponse(request, "components/peer_qr_modal.html", {
            "peer": peer,
            "qr_code": qr_base64,
            "config": config
        })
    except Exception as e:
        return modal_alert_response(request, "error", f"Ошибка: {str(e)}")


@router.get("/server-info", response_class=HTMLResponse)
async def server_info(
    request: Request,
    user: dict = Depends(require_auth),
    wg: WGManager = Depends(get_wg_manager)
):
    """Информация о сервере WireGuard"""
    try:
        info = wg.get_server_info()
        return templates.TemplateResponse(request, "components/server_info.html", {
            "server": info
        })
    except Exception as e:
        return alert_response(request, "error", f"Ошибка получения информации: {str(e)}")
